import os
from datetime import datetime

from data.models.models import Base, engine, get_session, Analyst, ExternalIOC


def initialize_schema() -> None:
    Base.metadata.create_all(bind=engine)


ANALYST_SEED_DATA = [
    {
        "id": 10,
        "name": "Clark Sullivan",
        "email": "c.sullivan.4t@gmail.com",
        "role": "analyst",
        "active": True,
        "notification_threshold": "low",
        "created_at": "2026-02-07 22:27:52.252847",
        "updated_at": "2026-03-13 17:20:26.189043",
        "password_hash": "scrypt:32768:8:1$HbN9EefZlddkufFC$d00f8512cabade3d8807694e270d062f1a69efa0e500c4ccc86bed28bcaa15d734003949e13c45ace7e219b0e4f7f24bbc34ff27d87ab9f6c783cff8bd409016",
        "last_login": "2026-03-05 12:46:28.533398+00",
        "must_change_password": False,
    },
    {
        "id": 12,
        "name": "James Kent",
        "email": "j.kent.4t@gmail.com",
        "role": "manager",
        "active": True,
        "notification_threshold": "critical",
        "created_at": "2026-02-07 22:27:52.257018",
        "updated_at": "2026-03-13 17:20:54.019008",
        "password_hash": "scrypt:32768:8:1$UGeCI34r2GC2Ay3J$430b119a6b2f5679691b3199f9c393db83ff10253dd1aa6caba40ba1092b6b8fc75cf1732318130365e5d94afec25094d1b05b00a91d5542c3fed6515be547bc",
        "last_login": None,
        "must_change_password": True,
    },
    {
        "id": 13,
        "name": "John Reynolds",
        "email": "j.reynolds.4t@gmail.com",
        "role": "analyst",
        "active": True,
        "notification_threshold": "low",
        "created_at": "2026-02-07 22:27:52.258672",
        "updated_at": "2026-03-13 17:21:02.074408",
        "password_hash": "scrypt:32768:8:1$zrR8O0PF1t534rwn$fbabfadf18500d7a31ff25f0764ab8643706478881aef1543b6f8028cdff140cc12500eb95f485a16d6b17dcaf3bd024029caf43415b60be74e99663b4f1e96f",
        "last_login": None,
        "must_change_password": True,
    },
    {
        "id": 14,
        "name": "Cody Lawrence",
        "email": "c.lawrence.4t@gmail.com",
        "role": "senior_analyst",
        "active": True,
        "notification_threshold": "medium",
        "created_at": "2026-02-07 22:27:52.260113",
        "updated_at": "2026-03-13 17:21:08.641959",
        "password_hash": "scrypt:32768:8:1$xHkdEGFwLSKZguzJ$88d05b94fe8de5c5d37ad4a340cb16a4c01ec38a623923c12fd7d877378a94fd0f20dd7e2cfc1adb43b9fee7f713a00539dd0e3260f9a1bbeaf61fb4b8ea2d05",
        "last_login": "2026-03-03 22:34:24.845758+00",
        "must_change_password": True,
    },
    {
        "id": 11,
        "name": "Pete Lang",
        "email": "p.lang.4t@gmail.com",
        "role": "admin",
        "active": True,
        "notification_threshold": "critical",
        "created_at": "2026-02-07 22:27:52.255274",
        "updated_at": "2026-04-25 01:40:31.04612",
        "password_hash": "scrypt:32768:8:1$V3P6arBMiPa5WFuk$8abbf20c84c4c64e8e538a74f325dabe9cf613c2b0fde4a049a7657e455ecc770efc02cba45b5416dc5f839ee74621876e94a22419ae6e70053d461add728758",
        "last_login": "2026-04-25 02:40:31.044602+01",
        "must_change_password": False,
    },
]


IOC_SEED_DATA = [
    {
        "id": 1,
        "indicator_type": "ip",
        "indicator_value": "185.220.101.45",
        "source": "test_data",
        "severity": "CRITICAL",
        "threat_actor": "APT28",
        "campaign": "Spear Phishing Campaign",
        "retrieved_at": "2026-04-04 05:01:25.018003+01",
        "expires_at": "2026-05-04 05:01:25.01451+01",
        "ioc_metadata": {
            "malware_family": None,
            "populated_at": "2026-04-04T04:01:25.016499+00:00",
        },
    },
    {
        "id": 2,
        "indicator_type": "domain",
        "indicator_value": "updates.legitimatecorp.ru",
        "source": "test_data",
        "severity": "CRITICAL",
        "threat_actor": "APT28",
        "campaign": "",
        "retrieved_at": "2026-04-04 05:01:25.020687+01",
        "expires_at": "2026-05-04 05:01:25.01451+01",
        "ioc_metadata": {
            "malware_family": None,
            "populated_at": "2026-04-04T04:01:25.020104+00:00",
        },
    },
    {
        "id": 3,
        "indicator_type": "ip",
        "indicator_value": "78.142.19.0",
        "source": "test_data",
        "severity": "ERROR",
        "threat_actor": "APT28",
        "campaign": "",
        "retrieved_at": "2026-04-04 05:01:25.0228+01",
        "expires_at": "2026-05-04 05:01:25.01451+01",
        "ioc_metadata": {
            "malware_family": None,
            "populated_at": "2026-04-04T04:01:25.022231+00:00",
        },
    },
    {
        "id": 4,
        "indicator_type": "domain",
        "indicator_value": "secure-updates.windowsdefender.info",
        "source": "test_data",
        "severity": "ERROR",
        "threat_actor": "Lazarus_Group",
        "campaign": "",
        "retrieved_at": "2026-04-04 05:01:25.024745+01",
        "expires_at": "2026-05-04 05:01:25.01451+01",
        "ioc_metadata": {
            "malware_family": None,
            "populated_at": "2026-04-04T04:01:25.024228+00:00",
        },
    },
    {
        "id": 5,
        "indicator_type": "ip",
        "indicator_value": "45.142.120.91",
        "source": "test_data",
        "severity": "CRITICAL",
        "threat_actor": "APT41",
        "campaign": "",
        "retrieved_at": "2026-04-04 05:01:25.026764+01",
        "expires_at": "2026-05-04 05:01:25.01451+01",
        "ioc_metadata": {
            "malware_family": None,
            "populated_at": "2026-04-04T04:01:25.026223+00:00",
        },
    },
    {
        "id": 6,
        "indicator_type": "ip",
        "indicator_value": "103.145.23.156",
        "source": "test_data",
        "severity": "CRITICAL",
        "threat_actor": "Emotet_Operators",
        "campaign": "",
        "retrieved_at": "2026-04-04 05:01:25.028675+01",
        "expires_at": "2026-05-04 05:01:25.01451+01",
        "ioc_metadata": {
            "malware_family": "Emotet",
            "populated_at": "2026-04-04T04:01:25.028159+00:00",
        },
    },
    {
        "id": 7,
        "indicator_type": "domain",
        "indicator_value": "adobe-update-manager.com",
        "source": "test_data",
        "severity": "ERROR",
        "threat_actor": "Turla",
        "campaign": "",
        "retrieved_at": "2026-04-04 05:01:25.030216+01",
        "expires_at": "2026-05-04 05:01:25.01451+01",
        "ioc_metadata": {
            "malware_family": None,
            "populated_at": "2026-04-04T04:01:25.029825+00:00",
        },
    },
    {
        "id": 8,
        "indicator_type": "ip",
        "indicator_value": "162.125.18.14",
        "source": "test_data",
        "severity": "ERROR",
        "threat_actor": "DarkSide",
        "campaign": "",
        "retrieved_at": "2026-04-04 05:01:25.031617+01",
        "expires_at": "2026-05-04 05:01:25.01451+01",
        "ioc_metadata": {
            "malware_family": None,
            "populated_at": "2026-04-04T04:01:25.031226+00:00",
        },
    },
    {
        "id": 9,
        "indicator_type": "domain",
        "indicator_value": "payment-processing-api.dataservices.net",
        "source": "test_data",
        "severity": "CRITICAL",
        "threat_actor": "FIN7",
        "campaign": "",
        "retrieved_at": "2026-04-04 05:01:25.032914+01",
        "expires_at": "2026-05-04 05:01:25.01451+01",
        "ioc_metadata": {
            "malware_family": None,
            "populated_at": "2026-04-04T04:01:25.032535+00:00",
        },
    },
    {
        "id": 10,
        "indicator_type": "ip",
        "indicator_value": "198.211.121.99",
        "source": "test_data",
        "severity": "ERROR",
        "threat_actor": "Carbanak",
        "campaign": "",
        "retrieved_at": "2026-04-04 05:01:25.034481+01",
        "expires_at": "2026-05-04 05:01:25.01451+01",
        "ioc_metadata": {
            "malware_family": None,
            "populated_at": "2026-04-04T04:01:25.033917+00:00",
        },
    },
    {
        "id": 11,
        "indicator_type": "domain",
        "indicator_value": "metrics-us-west.analytics-relay.net",
        "source": "test_data",
        "severity": "CRITICAL",
        "threat_actor": "Wizard_Spider",
        "campaign": "",
        "retrieved_at": "2026-04-04 05:01:25.036037+01",
        "expires_at": "2026-05-04 05:01:25.01451+01",
        "ioc_metadata": {
            "malware_family": None,
            "populated_at": "2026-04-04T04:01:25.035719+00:00",
        },
    },
]


def parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def upsert_analysts() -> int:
    session = get_session()
    upserted_count = 0
    try:
        for row in ANALYST_SEED_DATA:
            analyst = session.query(Analyst).filter_by(id=row["id"]).first()
            if analyst is None:
                analyst = session.query(Analyst).filter_by(email=row["email"]).first()

            if analyst is None:
                analyst = Analyst(id=row["id"])
                session.add(analyst)

            analyst.id = row["id"]
            analyst.name = row["name"]
            analyst.email = row["email"]
            analyst.role = row["role"]
            analyst.active = row["active"]
            analyst.notification_threshold = row["notification_threshold"]
            analyst.created_at = parse_datetime(row["created_at"])
            analyst.updated_at = parse_datetime(row["updated_at"])
            analyst.password_hash = row["password_hash"]
            analyst.last_login = parse_datetime(row["last_login"])
            analyst.must_change_password = row["must_change_password"]
            upserted_count += 1

        session.commit()
        return upserted_count
    finally:
        session.close()


def upsert_external_iocs() -> int:
    session = get_session()
    upserted_count = 0
    try:
        for row in IOC_SEED_DATA:
            ioc = session.query(ExternalIOC).filter_by(id=row["id"]).first()
            if ioc is None:
                ioc = (
                    session.query(ExternalIOC)
                    .filter_by(indicator_value=row["indicator_value"])
                    .first()
                )

            if ioc is None:
                ioc = ExternalIOC(id=row["id"])
                session.add(ioc)

            ioc.id = row["id"]
            ioc.indicator_type = row["indicator_type"]
            ioc.indicator_value = row["indicator_value"]
            ioc.source = row["source"]
            ioc.severity = row["severity"]
            ioc.threat_actor = row["threat_actor"]
            ioc.campaign = row["campaign"]
            ioc.retrieved_at = parse_datetime(row["retrieved_at"])
            ioc.expires_at = parse_datetime(row["expires_at"])
            ioc.ioc_metadata = row["ioc_metadata"]
            upserted_count += 1

        session.commit()
        return upserted_count
    finally:
        session.close()


def main() -> None:
    initialize_schema()

    if os.getenv("SKIP_DB_SEED", "false").lower() in {"1", "true", "yes"}:
        print("[init_database] SKIP_DB_SEED enabled; skipping seed data")
        print("[init_database] Schema initialization complete")
        return

    analysts_count = upsert_analysts()
    iocs_count = upsert_external_iocs()
    print(f"[init_database] Seeded analysts rows: {analysts_count}")
    print(f"[init_database] Seeded external_iocs rows: {iocs_count}")
    print("[init_database] Schema initialization complete")


if __name__ == "__main__":
    main()
