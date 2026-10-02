import requests
import os
from dotenv import load_dotenv
from typing import Dict, List
from data.models.models import ExternalIOC, get_session
from datetime import datetime, timezone

load_dotenv()

THREAT_ACTORS = {
    "APT29": {
        "aliases": ["Cozy Bear", "The Dukes"],
        "nation_state": True,
        "country": "Russia (SVR)",
        "tactics": ["TA0001", "TA0002", "TA0003", "TA0005"],
        "tools": ["WellMess", "GoldMax", "CozyDuke"],
    },
    "Lazarus": {
        "aliases": ["HIDDEN COBRA", "ZINC"],
        "nation_state": True,
        "country": "North Korea (RGB)",
        "tactics": ["TA0001", "TA0004", "TA0010"],
        "tools": ["Malwarebytes", "MATA", "AppleJeus"],
    },
    "APT41": {
        "aliases": ["Double Dragon", "Winnti Group"],
        "nation_state": True,
        "country": "China (MSS)",
        "tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0007"],
        "tools": ["Winnti", "ShadowPad", "Crosswalk"],
    },
    "FIN7": {
        "aliases": ["Carbanak Group", "Anunak"],
        "nation_state": False,
        "country": None,
        "tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0007"],
        "tools": ["Carbanak", "Cobalt Strike", "GandCrab"],
    },
    "Emotet": {
        "aliases": ["Mummy Spider"],
        "nation_state": False,
        "country": None,
        "tactics": ["TA0001", "TA0002", "TA0003", "TA0005"],
        "tools": ["Emotet Botnet"],
    },
    "TrickBot": {
        "aliases": ["TrickLoader"],
        "nation_state": False,
        "country": None,
        "tactics": ["TA0001", "TA0002", "TA0003", "TA0005"],
        "tools": ["TrickBot Botnet"],
    },
}


class ThreatIntelClient:
    """COnsume external threat intel feeds."""

    def __init__(self):
        self.sources = {
            "otx": os.getenv("OTX_API_KEY"),  # AlienVault OTX
            "misp": os.getenv("MISP_API_KEY"),  # MISP instance
            "abusedb": os.getenv("ABUSEDB_API_KEY"),  # AbuseIPDB
        }

    def fetch_otx_indicators(self, indicator=None):
        """Fetch indicators from AlienVault OTX."""
        headers = {"X-OTX-API-KEY": self.sources["otx"]}

        # Get indicators from OTX
        url = f"https://otx.alienvault.com/api/v1/indicators/pulse/subscribed?limit=50"

        try:
            resp = requests.get(url, headers=headers, timeout=5).json()
        except:
            return []

        indicators = []
        for pulse in resp.get("results", []):
            for ind in pulse.get("indicators", []):
                ind_value = ind.get("indicator", "")
                # Filter by indicator if provided
                if indicator and indicator not in ind_value:
                    continue
                indicators.append(
                    {
                        "type": ind.get("type", "unknown"),
                        "value": ind_value,
                        "severity": pulse.get("name", "unknown"),
                        "source": "OTX",
                        "tags": pulse.get("tags", []),
                    }
                )
        return indicators

    def fetch_misp_indicators(self, indicator=None):
        """Fetch indicators from MISP instance."""
        headers = {"Authorization": f"Bearer {os.getenv('MISP_API_KEY')}"}

        # Get latest IOCs
        misp_url = os.getenv("MISP_API_URL", "https://misp.circl.lu")
        url = f"{misp_url}/api/events/restSearch"
        params = {"limit": 200, "returnFormat": "json"}

        try:
            resp = requests.post(url, headers=headers, params=params, timeout=5).json()
        except:
            return []

        indicators = []
        for event in resp.get("response", []):
            for attr in event.get("Event", {}).get("Attribute", []):
                ind_value = attr.get("value", "")
                # Filter by indicator if provided
                if indicator and indicator not in ind_value:
                    continue
                indicators.append(
                    {
                        "type": attr.get("type", "unknown"),
                        "value": ind_value,
                        "source": "MISP",
                        "tags": [tag.get("name", "") for tag in attr.get("Tag", [])],
                    }
                )
        return indicators

    def fetch_abusedb_reputation(self, ip: str) -> Dict:
        """Check IP reputation from AbuseIPDB."""
        headers = {"Key": self.sources["abusedb"]}

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        resp = requests.get(url, headers=headers, params=params).json()
        return {
            "ip": ip,
            "abuse_score": resp["data"]["abuseConfidenceScore"],
            "total_reports": resp["data"]["totalReports"],
            "is_dangerous": resp["data"]["abuseConfidenceScore"] > 25,
        }

    def hunt_with_external_iocs(self, log_event):
        """Match log event against external IOCs in database."""
        if not log_event:
            return []

        session = get_session()
        iocs = session.query(ExternalIOC).all()

        matches = []
        matched_ioc_ids = set()  # Track to avoid duplicates

        # Build searchable text from classification
        search_fields = [
            str(log_event.get("message", "")),
            str(log_event.get("threat_type", "")),
            str(log_event.get("vulnerability_name", "")),
            str(log_event.get("asset_name", "")),
        ]
        searchable_text = " ".join(search_fields).lower()

        # Also get threat_actors list directly
        threat_actors_in_event = log_event.get("threat_actors", [])

        for ioc in iocs:
            if ioc.id in matched_ioc_ids:
                continue

            # Direct string match (IP, domain, hash, CVE)
            if ioc.indicator_value.lower() in searchable_text:
                if ioc.id not in matched_ioc_ids:
                    matches.append(
                        {
                            "ioc": ioc.indicator_value,
                            "type": ioc.indicator_type,
                            "source": ioc.source,
                            "threat_actor": ioc.threat_actor,
                            "campaign": ioc.campaign,
                            "severity": ioc.severity,
                        }
                    )
                    matched_ioc_ids.add(ioc.id)
                continue

            # Threat actor match - check threat_actors list directly
            if ioc.threat_actor:
                # Normalize threat actor name for comparison
                ioc_actor_normalized = (
                    ioc.threat_actor.lower().replace("_", " ").replace("-", " ")
                )

                # Check if this threat actor appears in the event's threat_actors list
                for event_actor in threat_actors_in_event:
                    event_actor_normalized = (
                        str(event_actor).lower().replace("_", " ").replace("-", " ")
                    )

                    if ioc_actor_normalized == event_actor_normalized:
                        if ioc.id not in matched_ioc_ids:
                            matches.append(
                                {
                                    "ioc": ioc.indicator_value,
                                    "type": ioc.indicator_type,
                                    "source": ioc.source,
                                    "threat_actor": ioc.threat_actor,
                                    "campaign": ioc.campaign,
                                    "severity": ioc.severity,
                                }
                            )
                            matched_ioc_ids.add(ioc.id)
                        break

        session.close()
        return matches

    def identify_threat_actor(self, indicators: List[str]) -> List[str]:
        """Identify likely threat actor from indicators"""

        session = get_session()
        iocs_in_event = (
            session.query(ExternalIOC)
            .filter(ExternalIOC.indicator_value.in_(indicators))
            .all()
        )

        actors = set()
        for ioc in iocs_in_event:
            if ioc.threat_actor:
                actors.add(ioc.threat_actor)

        return sorted(actors)

    def fetch_and_store_indicators(self):
        """Fetch indicators from all threat intel APIs and store in database.

        This is the automated pipeline that populates external_iocs table.
        Call this on startup or periodically to keep IOCs fresh.
        """
        from datetime import timedelta

        session = get_session()

        all_indicators = []

        # Fetch from OTX
        try:
            print("[ThreatIntel] Fetching indicators from OTX...")
            otx_indicators = self.fetch_otx_indicators()
            all_indicators.extend(otx_indicators)
            print(f"  ✓ Got {len(otx_indicators)} indicators from OTX")
        except Exception as e:
            print(f"  ℹ OTX fetch failed: {e}")

        # Fetch from MISP
        try:
            print("[ThreatIntel] Fetching indicators from MISP...")
            misp_indicators = self.fetch_misp_indicators()
            all_indicators.extend(misp_indicators)
            print(f"  ✓ Got {len(misp_indicators)} indicators from MISP")
        except Exception as e:
            print(f"  ℹ MISP fetch failed: {e}")

        # Fetch from AbuseDB (limited - only stores if we have IPs to check)
        try:
            print("[ThreatIntel] Fetching reputation data from AbuseDB...")
            # Note: AbuseDB has rate limits, so we don't fetch all
            print(f"  ℹ AbuseDB has strict rate limits, use selectively")
        except Exception as e:
            print(f"  ℹ AbuseDB fetch skipped: {e}")

        # Store in database
        if not all_indicators:
            print("[ThreatIntel] ⚠ No indicators fetched from APIs")
            return 0

        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        stored_count = 0

        try:
            for ind in all_indicators:
                # Check if already exists to avoid duplicates
                existing = (
                    session.query(ExternalIOC)
                    .filter(
                        ExternalIOC.indicator_value == ind["value"],
                        ExternalIOC.indicator_type == ind["type"],
                    )
                    .first()
                )

                if not existing:
                    ioc = ExternalIOC(
                        indicator_type=ind["type"],
                        indicator_value=ind["value"],
                        source=ind.get("source", "external_api"),
                        severity=ind.get("severity", "medium"),
                        threat_actor=ind.get("threat_actor"),
                        campaign=ind.get("campaign"),
                        expires_at=expires_at,
                        ioc_metadata={
                            "tags": ind.get("tags", []),
                            "fetched_at": datetime.now(timezone.utc).isoformat(),
                        },
                    )
                    session.add(ioc)
                    stored_count += 1

            session.commit()
            print(
                f"\n[ThreatIntel] ✅ Successfully stored {stored_count} new indicators"
            )
            return stored_count

        except Exception as e:
            session.rollback()
            print(f"[ThreatIntel] ❌ Error storing indicators: {e}")
            return 0
        finally:
            session.close()
