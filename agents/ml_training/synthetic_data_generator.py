import random
import string
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict

class SyntheticDataGenerator:
    """Generate labeled benign and malicious events"""

    # Benign process chains (normal user workflows)
    BENIGN_CHAINS = [
        ["explorer.exe", "notepad.exe"],
        ["explorer.exe", "chrome.exe"],
        ["explorer.exe", "word.exe", "outlook.exe"],
        ["services.exe", "svchost.exe"],
        ["winlogon.exe", "userinit.exe", "explorer.exe"],
        ["taskschd.exe", "taskhostw.exe"], 
    ]

    # Malicious process chains (attack patterns)
    MALICIOUS_CHAINS = [
        ["explorer.exe", "svchost.exe", "powershell.exe", "cmd.exe"], # Process replacement
        ["winword.exe", "cmd.exe", "powershell.exe"], # Office → cmd (common macro attack)
        ["chrome.exe", "rundll32.exe"], # Browser → rundll32 (dll hijacking)
        ["svchost.exe", "certutil.exe", "whoami.exe"], # Process impersonation
        ["explorer.exe", "psexec.exe", "cmd.exe"], # Lateral movement
        ["notepad.exe", "cmd.exe", "powershell.exe"], # Living-off-the-land
    ]

    BENIGN_DESTINATIONS = [
        ("1.1.1.1", 443),       # CloudFlare DNS over HTTPS
        ("8.8.8.8", 443),       # Google DNS
        ("44.55.66.77", 443),   # Generic cloud services
        ("10.0.0.1", 22),       # Internal SSh
        ("10.0.0.2", 3306),     # Internal database
    ]

    MALICIOUS_DESTINATIONS = [
        ("1.2.3.4", 4444),      # Known C2
        ("5.6.7.8", 5555),      # Known C2
        ("9.10.11.12", 8888),   # Suspicious port
        ("192.168.1.100", 3389),    # RDP (lateral movement)
        ("169.254.0.1", 9999),  # APIPA (suspicious)
    ]

    @staticmethod
    def generate_benign_processes(count: int = 5000) -> List[Dict]:
        """Generate benign process execution events"""
        events = []

        for _ in range(count):
            chain = random.choice(SyntheticDataGenerator.BENIGN_CHAINS)

            # Pick a process fro chain
            parent_name = chain[0] if len(chain) > 1 else "explorer.exe"
            process_name = chain[-1]

            # Benign command line
            if process_name == "svchost.exe":
                cmdline = f"C:\\Windows\\System32\\svchost.exe -k {random.choice(["netsvcs", "localsystemnetwork", "rpcss"])}"
            elif process_name == "powershell.exe":
                cmdline = f"C:\\Windows\\System32\\powershell.exe -NoProfile"
            else:
                cmdline = f"C:\\Program Files\\{process_name.replace(".exe", "")}\\{process_name}"

            event = {
                "pid": random.randint(1000, 100000),
                "ppid": random.randint(1000, 100000),
                "name": process_name,
                "path": f"C:\\Windows\\System32\\{process_name}" if "System32" in process_name else f"C:\\Program Files\\{process_name}",
                "command_line": cmdline,
                "parent_name": parent_name,
                "user": random.choice(["SYSTEM", "NT AUTHORITY\\LOCAL SERVICE", "Administrator"]),
                "create_time": (datetime.now() - timedelta(hours=random.randint(1, 168))).timestamp(),
                "is_first_seen": random.random() < 0.1, # 10% first-seen
                "label": 0 # Benign
            }
            events.append(event)

        return events

    @staticmethod
    def generate_malicious_processes(count: int = 5000) -> List[Dict]:
        """Generate malicious process execution events"""
        events = []

        for _ in range(count):
            chain = random.choice(SyntheticDataGenerator.MALICIOUS_CHAINS)

            parent_name = chain[0] if len(chain) > 1 else "explorer.exe"
            process_name = chain[-1]

            # Malicious command line (often obfuscated)
            obfuscation = "".join(random.choices(string.ascii_letters + string.digits, k=50))
            cmdline_options = [
                f"C:\\Windows\\System32\\{process_name} {obfuscation}",
                f"{process_name} -enc {obfuscation}",
                f"cmd.exe /c powershell -WindowStyle Hidden {obfuscation}",
                f"{process_name} -noprofile -noninteractive {obfuscation}",
            ]
            cmdline = random.choice(cmdline_options)

            event = {
                "pid": random.randint(1000, 100000),
                "ppid": random.randint(1000, 100000),
                "name": process_name,
                "path": f"C:\\{random.choice(["Temp", "ProgramData", "AppData"])}\\{process_name}", # Suspicious location
                "command_line": cmdline,
                "parent_name": parent_name,
                "user": random.choice(["Administrator", "Guest"]),
                "create_time": (datetime.now()- timedelta(hours=random.randint(1, 168))).timestamp(),
                "is_first_seen": random.random() < 0.5, # 50% first-seen (new malware)
                "label": 1 # Malicious
            }
            events.append(event)

        return events

    @staticmethod
    def generate_benign_connections(count: int = 5000) -> List[Dict]:
        """Generate benign network connection events"""
        events = []

        benign_processes = ["chrome.exe", "firefox.exe", "outlook.exe", "teams.exe", "slack.exe"]

        for _ in range(count):
            dst_ip, dst_port = random.choice(SyntheticDataGenerator.BENIGN_DESTINATIONS)

            event = {
                "source_ip": f"192.168.1.{random.randint(100, 200)}",
                "source_port": random.randint(1024, 65535),
                "dest_ip": dst_ip,
                "dest_port": dst_port,
                "process_name": random.choice(benign_processes),
                "protocol": "tcp",
                "bytes_sent": random.randint(100, 100000),
                "bytes_received": random.randint(1000, 1000000),
                "label": 0 # Benign
            }
            events.append(event)

        return events
    
    @staticmethod
    def generate_malicious_connections(count: int = 5000) -> List[Dict]:
        """Generate malicious network connection events"""
        events = []

        malicious_processes = ["svchost.exe", "rundll32.exe", "cmd.exe", "powershell.exe", "certutil.exe"]

        for _ in range(count):
            dst_ip, dst_port = random.choice(SyntheticDataGenerator.MALICIOUS_DESTINATIONS)

            event = {
                "source_ip": f"192.168.1.{random.randint(100, 200)}",
                "source_port": random.randint(49152, 65535),
                "dest_ip": dst_ip,
                "dest_port": dst_port,
                "process_name": random.choice(malicious_processes),
                "protocol": random.choice(["tcp", "udp"]),
                "bytes_sent": random.randint(10, 10000),
                "bytes_received": random.randint(10, 10000),
                "label": 1 # Malicious
            }    
            events.append(event)

        return events

    @staticmethod
    def generate_all(process_count: int = 5000, network_count: int = 5000) -> tuple:
        """Generate complete synthetic dataset"""
        process_benign = SyntheticDataGenerator.generate_benign_processes(process_count // 2)
        process_malicious = SyntheticDataGenerator.generate_malicious_processes(process_count // 2)
        process_events = process_benign + process_malicious
        random.shuffle(process_events)

        network_benign = SyntheticDataGenerator.generate_benign_connections(network_count // 2)
        network_malicious = SyntheticDataGenerator.generate_malicious_connections(network_count // 2 )
        network_events= network_benign + network_malicious
        random.shuffle(network_events)

        return process_events, network_events
    

# Usage example
if __name__ == "__main__":
    gen = SyntheticDataGenerator()
    process_events, network_events = gen.generate_all(process_count=10000, network_count=10000)

    print(f"Generated {len(process_events)} process events")
    print(f"Generated {len(network_events)} network events")
    print("\nSample benign process event: ", process_events[0])
    print("\nSample malicious process event: ", process_events[-1])
    print("\nSample benign network event: ", network_events[0])
    print("\nSample malicious network event: ", network_events[-1])
    