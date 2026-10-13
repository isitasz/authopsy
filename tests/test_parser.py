
import unittest
from src.main import parse_log_line


class TestParseLogLine(unittest.TestCase):
    def test_valid_failed_login(self):
        line = (
            "Oct 10 10:01:02 server sshd[1201]: "
            "Failed password for invalid user admin "
            "from 203.0.113.10 port 51234 ssh2"
        )

        event, error = parse_log_line(line)
        self.assertIsNone(error)
        self.assertEqual(event["timestamp"], "Oct 10 10:01:02")
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["ip"], "203.0.113.10")
        self.assertEqual(event["port"], 51234)
        self.assertEqual(event["hostname"], "server")
        self.assertEqual(event["process"], "sshd")
        self.assertEqual(event["pid"], 1201)
    
    def test_successful_login_is_ignored(self):
        line = (
            "Oct 10 10:01:21 server sshd[1204]: "
            "Accepted password for isabella "
            "from 192.0.2.15 port 50021 ssh2"
        )

        event, error = parse_log_line(line)
        self.assertIsNone(event)
        self.assertIsNone(error)

    def test_invalid_ip(self):
        line = (
            "Oct 10 10:04:00 server sshd[1300]: "
            "Failed password for admin "
            "from 999.999.999.999 port 51250 ssh2"
        )

        event, error = parse_log_line(line)
        self.assertIsNone(event)
        self.assertEqual(error, "invalid_ip")

    def test_missing_port(self):
        line = (
            "Oct 10 10:04:00 server sshd[1300]: "
            "Failed password for admin from 203.0.113.50 port ssh2"
        )

        event, error = parse_log_line(line)
        self.assertIsNone(event)
        self.assertEqual(error, "missing_port")

    def test_missing_timestamp(self):
        line = (
            "server sshd[1300]: "
            "Failed password for admin from 203.0.113.50 port 51250 ssh2"
        )

        event, error = parse_log_line(line)
        self.assertIsNone(event)
        self.assertEqual(error, "missing_timestamp")

    def test_missing_username(self):
        line = (
            "Oct 10 10:04:00 server sshd[1300]: "
            "Failed password for from 203.0.113.50 port 51250 ssh2"
        )

        event, error = parse_log_line(line)

        self.assertIsNone(event)
        self.assertEqual(error, "missing_user")

    def test_missing_ip(self):
        line = (
            "Oct 10 10:04:00 server sshd[1300]: "
            "Failed password for admin ssh2"
        )

        event, error = parse_log_line(line)
        self.assertIsNone(event)
        self.assertEqual(error, "missing_ip")

    def test_missing_hostname(self):
        line = (
            "Oct 10 10:04:00 sshd[1300]: "
            "Failed password for admin from 203.0.113.50 port 51250 ssh2"
        )

        event, error = parse_log_line(line)
        self.assertIsNone(event)
        self.assertEqual(error, "missing_hostname")

    def test_missing_process(self):
        line = (
            "Oct 10 10:04:00 server [1300]: "
            "Failed password for admin from 203.0.113.50 port 51250 "
        )

        event, error = parse_log_line(line)
        self.assertIsNone(event)
        self.assertEqual(error, "missing_process")

    def test_missing_pid(self):
        line = (
            "Oct 10 10:04:00 server sshd: "
            "Failed password for admin from 203.0.113.50 port 51250 ssh2"
        )

        event, error = parse_log_line(line)
        self.assertIsNone(event)
        self.assertEqual(error, "missing_pid")


if __name__ == "__main__":
    unittest.main()
