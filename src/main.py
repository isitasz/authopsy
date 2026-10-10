
from pathlib import Path


def main():
    log_path = Path("data/auth.log")
    attempts_by_ip = {}

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            if "Failed password" not in line:
                continue

            parts = line.split(" from ", 1)

            if len(parts) < 2:
                continue

            ip = parts[1].split()[0]

            if ip not in attempts_by_ip:
                attempts_by_ip[ip] = 0

            attempts_by_ip[ip] += 1

    for ip, attempts in attempts_by_ip.items():
        print(f"{ip}: {attempts} failed attempts")


if __name__ == "__main__":
    main()
