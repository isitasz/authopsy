
import ipaddress
import re
from pathlib import Path

def parse_log_line(line):

    if "Failed password" not in line:
        return None, None

    parts = line.split()
    timestamp = " ".join(parts[:3]) if len(parts) >= 3 else None

    match = re.search(r"Failed password for (?:invalid user )?(\w+) from (\S+)", line)
    user = match.group(1) if match else None
    ip = match.group(2) if match else None

    match = re.search(r"from \S+ port (\d+)", line)
    port = int(match.group(1)) if match else None

    match = re.search(r"(\w+) (\w+)\[(\d+)\]", line)
    hostname = match.group(1) if match else None
    process = match.group(2) if match else None
    pid = int(match.group(3)) if match else None

    fields = {
        "timestamp": timestamp,
        "username": user,
        "ip": ip,
        "port": port,
        "hostname": hostname,
        "process": process,
        "pid": pid
    }

    missing_fields = {
        "timestamp": "missing_timestamp",
        "username": "missing_user",
        "ip": "missing_ip",
        "port": "missing_port",
        "hostname": "missing_hostname",
        "process": "missing_process",
        "pid": "missing_pid"
    }

    for field, reason in missing_fields.items():
        if fields[field] is None:
            return None, reason

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None, "invalid_ip"

    return fields, None


def main():
    log_path = Path("data/auth.log")
    events=[]
    users_by_ip = {}
    attempts_by_ip = {}
    malformed_entries = {
        "invalid_ip": 0,
        "missing_ip": 0,
        "missing_timestamp": 0,
        "missing_port": 0,
        "missing_user": 0,
        "missing_hostname": 0,
        "missing_process": 0,
        "missing_pid": 0
    }

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            event, error = parse_log_line(line)

            if error is not None:
                malformed_entries[error] += 1
                continue
            if event is None:
                continue

            events.append(event)

            ip = event["ip"]
            attempts_by_ip[ip] = attempts_by_ip.get(ip, 0) + 1
            
    for event in events:
        ip = event["ip"]
        user = event["username"]

        if ip not in users_by_ip:
            users_by_ip[ip] = set()

        users_by_ip[ip].add(user)

    for ip, users in users_by_ip.items():
        if len(users) >= 3:
            print(f"{ip} has failed login attempts for multiple users: {', '.join(users)}")

    for ip, attempts in attempts_by_ip.items():
        print(f"{ip}: {attempts} failed attempts")
        if attempts >= 5:
            print(f"{ip} is potentially involved in a brute force attack!")

    print("\nMalformed entries:")
    for reason, count in malformed_entries.items():
            print(f"{reason}: {count}")
        


if __name__ == "__main__":
    main()
