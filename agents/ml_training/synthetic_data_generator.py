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
        ["explorer.exe", "svchost.exe", "powershell.exe", "cmd.exe"],
        ["winword.exe", "cmd.exe", "powershell.exe"],
        ["chrome.exe", "rundll32.exe"],
        ["svchost.exe", "certutil.exe", "whoami.exe"],
        ["explorer.exe", "psexec.exe", "cmd.exe"],
        ["notepad.exe", "cmd.exe", "powershell.exe"],
        ["explorer.exe", "cmd.exe", "attrib.exe"],
        ["explorer.exe", "cmd.exe", "icacls.exe"],
        ["explorer.exe", "cmd.exe", "vssadmin.exe"],
        ["svchost.exe", "rundll32.exe"],
        ["explorer.exe", "schtasks.exe"],
        ["explorer.exe", "cmd.exe", "netsh.exe"],
        ["winword.exe", "cmd.exe", "java.exe"],
        ["msedge.exe", "cmd.exe", "powershell.exe"],
        ["excel.exe", "mshta.exe"],
    ]

    BENIGN_DESTINATIONS = [
        ("1.1.1.1", 443),
        ("8.8.8.8", 443),
        ("44.55.66.77", 443),
        ("10.0.0.1", 22),
        ("10.0.0.2", 3306),
    ]

    MALICIOUS_DESTINATIONS = [
        ("1.2.3.4", 4444),
        ("5.6.7.8", 5555),
        ("9.10.11.12", 8888),
        ("192.168.1.100", 3389),
        ("169.254.0.1", 9999),
    ]

    @staticmethod
    def generate_benign_processes(count: int = 5000) -> List[Dict]:
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
        events = []

        for _ in range(count):
            chain = random.choice(SyntheticDataGenerator.MALICIOUS_CHAINS)

            parent_name = chain[0] if len(chain) > 1 else "explorer.exe"
            process_name = chain[-1]

            # Malicious command line (often obfuscated)
            obfuscation = "".join(random.choices(string.ascii_letters + string.digits, k=50))
            random_name = "".join(random.choices(string.ascii_lowercase, k=8))

            if process_name == "attrib.exe":
                target = random.choice([
                    f"C:\\Users\\{random_name}\\Desktop\\{random_name}.exe",
                    f"C:\\Users\\{random_name}\\Desktop",
                    f"C:\\Users\\{random_name}\\Documents\\{random_name}.exe"
                ])
                flags = random.choice(["+s +h", "+h", "+s +h +r"])
                cmdline = f'attrib "{target}" {flags}'
            elif process_name == "icacls.exe":
                target = random.choice([".", "C:\\Users", f"C:\\Users\\{random_name}"])
                cmdline = f'icacls "{target}" /grant Everyone:F /T /C /Q'
            elif process_name == "vssadmin.exe":
                cmdline = "vssadmin delete shadows /all /quiet"
            elif process_name == "netsh.exe":
                port = random.choice(["4444", "8080", "5555", "1337"])
                cmdline = random.choice([
                    f"netsh firewall add allowedprogram C:\\Users\\{random_name}\\server.exe {random_name} ENABLED",
                    f'netsh advfirewall firewall add rule name="{random_name}" dir=in action=allow protocol=TCP localport={port}',
                ])
            elif process_name == "schtasks.exe":
                task_name = random.choice(["rhaegal", "drogon", "WindowsUpdate", random_name])
                cmdline = random.choice([
                    f'schtasks /Create /RU SYSTEM /SC ONSTART /TN {task_name} /TR "C:\\Users\\{random_name}\\AppData\\Roaming\\{random_name}.exe"',
                ])
            elif process_name == "rundll32.exe":
                dll_name = random.choice(["infpub.dat", f"{random_name}.dll", f"{random_name}.dat"])
                ordinal = random.randint(1, 15)
                cmdline = f"C:\\Windows\\System32\\rundll32.exe C:\\Windows\\{dll_name},#{ordinal}"
            elif process_name == "java.exe":
                jar_name = "".join(random.choices(string.ascii_letters, k=12)) + ".jar"
                cmdline = f'java.exe -jar "C:\\Users\\{random_name}\\AppData\\Roaming\\{jar_name}"'
            elif process_name == "mshta.exe":
                cmdline = f'mshta.exe "C:\\Users\\{random_name}\\AppData\\Local\\Temp\\{random_name}.hta"'
            else:
                cmdline_options = [
                    f"C:\\Windows\\System32\\{process_name} {obfuscation}",
                    f"{process_name} -enc {obfuscation}",
                    f"cmd.exe /c powershell -WindowStyle Hidden {obfuscation}",
                    f"{process_name} -noprofile -noninteractive {obfuscation}",
                ]
                cmdline = random.choice(cmdline_options)

            appdata_path = f"C:\\Users\\{random_name}\\AppData\\Roaming\\{process_name}"
            path_options = [
                f"C:\\Temp\\{process_name}",
                f"C:\\ProgramData\\{process_name}",
                appdata_path,
                f"C:\\Windows\\System32\\{process_name}",
                f"C:\\Users\\{random_name}\\Desktop\\{process_name}",
            ]

            event = {
                "pid": random.randint(1000, 100000),
                "ppid": random.randint(1000, 100000),
                "name": process_name,
                "path": random.choice(path_options),
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
    