import argparse
import glob
import os
import shutil
import sys


WINDOWS_PATHS = [
    r"C:\Windows\System32\*.exe",
    r"C:\Windows\System32\*.dll",
    r"C:\Program Files\**\*.exe",
]

LINUX_PATHS = [
    "/usr/bin/*",
    "/usr/sbin/*",
    "/usr/lib/**/*.so",
    "/usr/lib/**/*.so.*",
]


def collect(patterns: list, output_dir: str, max_samples: int):
    os.makedirs(output_dir, exist_ok=True)
    collected = 0

    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            if collected >= max_samples:
                return collected
            if not os.path.isfile(path):
                continue
            try:
                size = os.path.getsize(path)
                if size < 1024 or size > 50_000_000:
                    continue
                dest = os.path.join(output_dir, f"{collected:05d}_{os.path.basename(path)}")
                shutil.copy2(path, dest)
                collected += 1
            except (PermissionError, OSError):
                continue

    return collected


def main():
    parser = argparse.ArgumentParser(description="Collect benign samples for training")
    parser.add_argument("--os", choices=["windows", "linux"], required=True)
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument("--max", type=int, default=500, help="Max samples to collect")
    args = parser.parse_args()

    patterns = WINDOWS_PATHS if args.os == "windows" else LINUX_PATHS

    print(f"[*] Collecting up to {args.max} benign {args.os} samples...")
    count = collect(patterns, args.output, args.max)
    print(f"[✓] Collected {count} samples in {args.output}")


if __name__ == "__main__":
    main()