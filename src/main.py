
import ipaddress
from pathlib import Path


def main():
    log_path = Path("data/auth.log")
    attempts_by_ip = {}
    events=[]

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            if "Failed password" not in line:
                continue

            parts = line.split(" from ", 1)

            if len(parts) < 2:
                continue

            try:
                ip = parts[1].split()[0]
                ipaddress.ip_address(ip)
            except ValueError:
                continue

            if "invalid user" in line:
                parts = line.split(" user ", 1)
                user = parts[1].split()[0]
                print(f"{user}")
            else:
                parts = line.split(" for ", 1)
                user = parts[1].split()[0]
                print(f"{user}")

            timestamp = " ".join(line.split()[:3])

            parts = line.split(" port ", 1)
            port = int(parts[1].split()[0])

            hostname = line.split()[3]

            process = line.split()[4].split("[")[0]

            parts = line.split("[", 1)
            pid = int(parts[1].split("]")[0])

            event = {
                "timestamp": timestamp,
                "username": user,
                "ip": ip,
                "port": port,
                "hostname": hostname,
                "pid": pid,
                "process": process
            }

            events.append(event)
            

            if ip not in attempts_by_ip:
                attempts_by_ip[ip] = 0

            attempts_by_ip[ip] += 1

    for ip, attempts in attempts_by_ip.items():
        print(f"{ip}: {attempts} failed attempts")

    print(events)
        


if __name__ == "__main__":
    main()
