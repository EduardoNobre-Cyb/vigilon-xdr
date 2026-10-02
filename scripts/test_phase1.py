#!/usr/bin/env python3
"""
Phase 1 Testing: Log Ingestion & Heuristic Threat Detection
Tests the Vigilon Intake log ingestor and basic threat detection rules
"""

import os
import json
from datetime import datetime
from pathlib import Path

# Setup test data directory
TEST_LOG_DIR = Path("test_logs")
TEST_LOG_DIR.mkdir(exist_ok=True)

def create_test_logs():
    """Generate sample logs for testing Phase 1"""
    
    # 1. Syslog format test
    syslog_content = """Jun 17 10:23:45 server01 sshd[1234]: Failed password for root from 192.168.1.100
Jun 17 10:24:10 server01 sshd[1235]: Accepted publickey for admin from 192.168.1.50
Jun 17 10:25:00 server01 sudo[2000]: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash
Jun 17 10:26:15 webserver nginx[5000]: 192.168.1.100 - - [17/Jun/2026:10:26:15 +0000] "GET /admin HTTP/1.1" 403 512
Jun 17 10:27:30 webserver nginx[5001]: 10.0.0.50 - - [17/Jun/2026:10:27:30 +0000] "POST /login HTTP/1.1" 401 256
Jun 17 10:28:45 firewall kernel: SYN flood attack detected from 203.0.113.55
Jun 17 10:29:00 server01 sshd[1240]: Invalid user attempt from 198.51.100.0
"""
    (TEST_LOG_DIR / "syslog.log").write_text(syslog_content)
    print("✓ Created syslog.log")
    
    # 2. JSON format test
    json_logs = [
        {"timestamp": "2026-06-17T10:30:00Z", "service": "authentication", "user": "admin", "action": "login", "status": "success", "ip": "192.168.1.50"},
        {"timestamp": "2026-06-17T10:31:00Z", "service": "authentication", "user": "attacker", "action": "login", "status": "failed", "ip": "203.0.113.55", "attempts": 10},
        {"timestamp": "2026-06-17T10:32:00Z", "service": "file_access", "user": "admin", "file": "/etc/shadow", "action": "read", "status": "denied"},
        {"timestamp": "2026-06-17T10:33:00Z", "service": "network", "event": "port_scan", "source_ip": "198.51.100.0", "ports_scanned": 1024},
        {"timestamp": "2026-06-17T10:34:00Z", "service": "malware", "file": "exploit.exe", "status": "quarantined", "signature": "CVE-2024-1234"},
    ]
    (TEST_LOG_DIR / "events.json").write_text("\n".join(json.dumps(log) for log in json_logs))
    print("✓ Created events.json")
    
    # 3. CSV format test
    csv_content = """timestamp,user,action,result,severity
2026-06-17T10:35:00Z,root,privilege_escalation,success,CRITICAL
2026-06-17T10:36:00Z,guest,file_delete,success,HIGH
2026-06-17T10:37:00Z,service_account,data_exfil,blocked,CRITICAL
2026-06-17T10:38:00Z,admin,config_change,success,MEDIUM
"""
    (TEST_LOG_DIR / "audit.csv").write_text(csv_content)
    print("✓ Created audit.csv")

def test_log_ingestor():
    """Test Phase 1: Log Ingestor"""
    from agents.log_ingestor.log_ingestor_agent1 import LogIngestor
    
    print("\n" + "="*60)
    print("PHASE 1: Testing Log Ingestion")
    print("="*60)
    
    # Create test logs
    create_test_logs()
    
    # Define sources
    sources = [
        {"type": "file", "path": str(TEST_LOG_DIR / "syslog.log")},
        {"type": "file", "path": str(TEST_LOG_DIR / "events.json")},
        {"type": "file", "path": str(TEST_LOG_DIR / "audit.csv")},
    ]
    
    # Ingest logs
    print("\n[*] Ingesting logs from multiple sources...")
    ingestor = LogIngestor(sources, batch_size=100)
    events = ingestor.ingest()
    
    print(f"\n✓ Total events ingested: {len(events)}")
    
    # Show sample events
    print("\n[*] Sample ingested events:")
    for i, event in enumerate(events[:5]):
        print(f"\n  Event {i+1}:")
        for key, val in list(event.items())[:5]:  # Show first 5 fields
            print(f"    {key}: {val}")
    
    return events

def test_threat_detection(events):
    """Test Phase 1: Basic threat detection rules"""
    print("\n" + "="*60)
    print("PHASE 1: Testing Threat Detection (Heuristic Rules)")
    print("="*60)
    
    # Simple heuristic rules
    threats_detected = {
        "failed_login_attempts": 0,
        "privilege_escalation": 0,
        "port_scans": 0,
        "malware_indicators": 0,
        "brute_force": 0,
    }
    
    print("\n[*] Applying heuristic detection rules...")
    
    for event in events:
        event_str = json.dumps(event).lower()
        
        # Rule 1: Failed login attempts
        if "failed" in event_str and ("password" in event_str or "login" in event_str):
            threats_detected["failed_login_attempts"] += 1
        
        # Rule 2: Privilege escalation
        if any(keyword in event_str for keyword in ["privilege", "sudo", "root", "escalation"]):
            threats_detected["privilege_escalation"] += 1
        
        # Rule 3: Port scanning
        if "port" in event_str and "scan" in event_str:
            threats_detected["port_scans"] += 1
        
        # Rule 4: Malware indicators
        if any(keyword in event_str for keyword in ["malware", "exploit", "quarantine", "cve"]):
            threats_detected["malware_indicators"] += 1
        
        # Rule 5: Brute force (multiple attempts)
        if "attempts" in event_str and int(event.get("attempts", 0)) > 5:
            threats_detected["brute_force"] += 1
    
    print("\n   Threats detected:")
    for threat_type, count in threats_detected.items():
        if count > 0:
            print(f"   ✓ {threat_type}: {count}")
        else:
            print(f"   • {threat_type}: {count}")
    
    total_threats = sum(threats_detected.values())
    print(f"\n   Total threat indicators: {total_threats}")
    
    return threats_detected

def main():
    print("\n" + "="*60)
    print("PHASE 1: Complete Log Ingestion & Detection Test")
    print("="*60)
    
    try:
        # Test log ingestor
        events = test_log_ingestor()
        
        if not events:
            print("\n❌ No events ingested!")
            return False
        
        # Test threat detection
        threats = test_threat_detection(events)
        
        print("\n" + "="*60)
        print("✓ Phase 1 Testing Complete!")
        print("="*60)
        print("\n[Summary]")
        print(f"  Events ingested: {len(events)}")
        print(f"  Threats detected: {sum(threats.values())}")
        print(f"  Success: {len(events) > 0 and sum(threats.values()) > 0}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error during Phase 1 testing: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
