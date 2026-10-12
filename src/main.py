
import ipaddress
import re
from pathlib import Path


def main():
    log_path = Path("data/auth.log")
    attempts_by_ip = {}
    events=[]
    users_by_ip = {}

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            if "Failed password" not in line:
                continue


            parts = line.split()
            timestamp = " ".join(parts[:3]) if len(parts) >= 3 else None

            match = re.search(r"Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)", line)
            user = match.group(1) if match else None

            try:
                ip = match.group(2) if match else None
                ipaddress.ip_address(ip)
            except ValueError:
                continue

            match = re.search(r"from \d+\.\d+\.\d+\.\d+ port (\d+)", line)
            port = int(match.group(1)) if match else None

            match = re.search(r"(\w+) (\w+)\[(\d+)\]", line)
            hostname = match.group(1) if match else None
            process = match.group(2) if match else None
            pid = int(match.group(3)) if match else None

            event = {
                "timestamp": timestamp,
                "username": user,
                "ip": ip,
                "port": port,
                "hostname": hostname,
                "process": process,
                "pid": pid
            }

            events.append(event)

            if ip not in attempts_by_ip:
                attempts_by_ip[ip] = 0
            
            attempts_by_ip[ip] += 1
    

    for event in events:
        ip = event["ip"]
        user = event["username"]

        if ip not in users_by_ip:
            users_by_ip[ip] = set();

        users_by_ip[ip].add(user)

    for ip, users in users_by_ip.items():
        if len(users) >= 3:
            print(f"{ip} has failed login attempts for multiple users: {', '.join(users)}")


    for ip, attempts in attempts_by_ip.items():
        print(f"{ip}: {attempts} failed attempts")
        if attempts >= 5:
            print(f"{ip} is potentially involved in a brute force attack!")


        


if __name__ == "__main__":
    main()
