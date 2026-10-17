import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

OUTPUT_FILE = Path("data/labelled/labelled_events.csv")

NORMAL_IPS = [
    "192.168.10.25",
    "192.168.10.31",
    "192.168.10.42",
    "192.168.10.18",
]

USERS = [
    "alice",
    "bob",
    "charlie",
    "david",
    "emma",
]

FIELDNAMES = [
    "timestamp",
    "event_type",
    "event_category",
    "source_ip",
    "username",
    "service",
    "status",
    "http_method",
    "http_path",
    "response_code",
    "label",
    "attack_category",
    "reason",
]


def build_events():
    events = []
    base_time = datetime(2026, 9, 25, 8, 0, 0)
    for i in range(13):
        ts = (base_time + timedelta(minutes=i)).isoformat()
        events.append({
            "timestamp": ts,
            "event_type": "LOGIN_SUCCESS",
            "event_category": "authentication",
            "source_ip": "192.168.10.25",
            "username": "alice",
            "service": "ssh",
            "status": "success",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "normal",
            "attack_category": "",
            "reason": "Normal user session",
        })
    for i in range(49):
        ts = (base_time + timedelta(hours=1, seconds=i * 10)).isoformat()
        events.append({
            "timestamp": ts,
            "event_type": "LOGIN_FAILED",
            "event_category": "authentication",
            "source_ip": "192.168.10.55",
            "username": "alice",
            "service": "ssh",
            "status": "failed",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "suspicious",
            "attack_category": "brute_force",
            "reason": "Repeated failed login attempts",
        })
    return events


def generate_normal_login(timestamp, source_ip, username):
    return {
        "timestamp": timestamp,
        "event_type": "LOGIN_SUCCESS",
        "event_category": "authentication",
        "source_ip": source_ip,
        "username": username,
        "service": "ssh",
        "status": "success",
        "http_method": "",
        "http_path": "",
        "response_code": "",
        "label": "normal",
        "attack_category": "",
        "reason": "",
    }


def generate_failed_login(timestamp, source_ip, username):
    return {
        "timestamp": timestamp,
        "event_type": "LOGIN_FAILED",
        "event_category": "authentication",
        "source_ip": source_ip,
        "username": username,
        "service": "ssh",
        "status": "failed",
        "http_method": "",
        "http_path": "",
        "response_code": "",
        "label": "suspicious",
        "attack_category": "brute_force",
        "reason": "Repeated authentication failures",
    }


def generate_web_request(
    timestamp,
    source_ip,
    path,
    response_code,
):
    label = "normal"
    attack_category = ""
    reason = ""

    if response_code in [403, 404]:
        label = "suspicious"
        attack_category = "repeated_4xx"
        reason = "Repeated client error responses"

    return {
        "timestamp": timestamp,
        "event_type": "HTTP_REQUEST",
        "event_category": "web",
        "source_ip": source_ip,
        "username": "",
        "service": "http",
        "status": "success" if response_code == 200 else "error",
        "http_method": "GET",
        "http_path": path,
        "response_code": response_code,
        "label": label,
        "attack_category": attack_category,
        "reason": reason,
    }


def generate_dataset():
    events = []
    base_time = datetime(2026, 9, 25, 9, 0, 0)

    # --- NORMAL EVENTS (70 events) ---
    # 20 normal logins (each user uses their own dedicated IP)
    for i in range(20):
        t = (base_time + timedelta(minutes=i * 10)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "LOGIN_SUCCESS",
            "event_category": "authentication",
            "source_ip": f"192.168.1.{10+i}",
            "username": f"normal_user_{i}",
            "service": "ssh",
            "status": "success",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "normal",
            "attack_category": "",
            "reason": "Normal authenticated user session",
        })
    # 20 normal web requests (1 per IP, 200 OK to public pages)
    for i in range(20):
        t = (base_time + timedelta(minutes=i * 10 + 2)).isoformat()
        path = ["/home", "/about", "/contact", "/services", "/products"][i % 5]
        events.append({
            "timestamp": t,
            "event_type": "HTTP_REQUEST",
            "event_category": "web",
            "source_ip": f"192.168.2.{10+i}",
            "username": "",
            "service": "http",
            "status": "success",
            "http_method": "GET",
            "http_path": path,
            "response_code": 200,
            "label": "normal",
            "attack_category": "",
            "reason": "Normal web page browsing",
        })
    # 10 normal app events
    for i in range(10):
        t = (base_time + timedelta(minutes=i * 20)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "APP_LOG",
            "event_category": "application",
            "source_ip": f"192.168.3.{10+i}",
            "username": "",
            "service": "inventory",
            "status": "success",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "normal",
            "attack_category": "",
            "reason": "Normal application transaction",
        })
    # 10 normal firewall events (ALLOW)
    for i in range(10):
        t = (base_time + timedelta(minutes=i * 20 + 5)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "FIREWALL_EVENT",
            "event_category": "firewall",
            "source_ip": f"192.168.4.{10+i}",
            "username": "",
            "service": "tcp/443",
            "status": "ALLOW",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "normal",
            "attack_category": "",
            "reason": "Legitimate firewall allowed connection",
        })
    # 10 normal system events
    for i in range(10):
        t = (base_time + timedelta(minutes=i * 20 + 8)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "SYSTEM_EVENT",
            "event_category": "system",
            "source_ip": f"192.168.5.{10+i}",
            "username": "",
            "service": "cron",
            "status": "running",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "normal",
            "attack_category": "",
            "reason": "Routine system service active",
        })

    # --- SUSPICIOUS EVENTS (15 scenarios) ---
    # AUTH-001 Multiple Failed Logins: 6 failed logins from 10.100.1.1
    for i in range(6):
        t = (base_time + timedelta(hours=1, seconds=i * 5)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "LOGIN_FAILED",
            "event_category": "authentication",
            "source_ip": "10.100.1.1",
            "username": "admin_victim",
            "service": "ssh",
            "status": "failed",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "suspicious",
            "attack_category": "brute_force",
            "reason": "Multiple failed logins",
        })
    # AUTH-002 Repeated Access Denied: 4 access denied from 10.100.1.2
    for i in range(4):
        t = (base_time + timedelta(hours=1, minutes=10, seconds=i * 5)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "ACCESS_DENIED",
            "event_category": "authentication",
            "source_ip": "10.100.1.2",
            "username": "restricted_user",
            "service": "ssh",
            "status": "denied",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "suspicious",
            "attack_category": "repeated_access_denied",
            "reason": "Repeated access denied",
        })
    # AUTH-003 Unusual Login Time: login at 02:15 AM
    events.append({
        "timestamp": "2026-09-25T02:15:00",
        "event_type": "LOGIN_SUCCESS",
        "event_category": "authentication",
        "source_ip": "10.100.1.3",
        "username": "night_crawler",
        "service": "ssh",
        "status": "success",
        "http_method": "",
        "http_path": "",
        "response_code": "",
        "label": "suspicious",
        "attack_category": "unusual_login_time",
        "reason": "Login outside business hours",
    })
    # AUTH-004 Successful Login After Failures: 4 failures + 1 success within 60s
    for i in range(4):
        t = (base_time + timedelta(hours=1, minutes=20, seconds=i * 10)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "LOGIN_FAILED",
            "event_category": "authentication",
            "source_ip": "10.100.1.4",
            "username": "compromised_acc",
            "service": "ssh",
            "status": "failed",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "suspicious",
            "attack_category": "successful_login_after_failures",
            "reason": "Prior failed attempt",
        })
    events.append({
        "timestamp": (base_time + timedelta(hours=1, minutes=20, seconds=45)).isoformat(),
        "event_type": "LOGIN_SUCCESS",
        "event_category": "authentication",
        "source_ip": "10.100.1.4",
        "username": "compromised_acc",
        "service": "ssh",
        "status": "success",
        "http_method": "",
        "http_path": "",
        "response_code": "",
        "label": "suspicious",
        "attack_category": "successful_login_after_failures",
        "reason": "Login after repeated failures",
    })
    # AUTH-005 Password Spraying: 5 accounts targeted from 10.100.1.5 in 60s
    for i, user in enumerate(["spray_u1", "spray_u2", "spray_u3", "spray_u4", "spray_u5"]):
        t = (base_time + timedelta(hours=1, minutes=30, seconds=i * 10)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "LOGIN_FAILED",
            "event_category": "authentication",
            "source_ip": "10.100.1.5",
            "username": user,
            "service": "ssh",
            "status": "failed",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "suspicious",
            "attack_category": "password_spraying",
            "reason": "Password spraying across accounts",
        })
    # AUTH-006 Multiple Account Targeting: 5 accounts targeted from 10.100.1.6
    for i, user in enumerate(["tgt_u1", "tgt_u2", "tgt_u3", "tgt_u4", "tgt_u5"]):
        t = (base_time + timedelta(hours=1, minutes=40, seconds=i * 10)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "LOGIN_FAILED",
            "event_category": "authentication",
            "source_ip": "10.100.1.6",
            "username": user,
            "service": "ssh",
            "status": "failed",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "suspicious",
            "attack_category": "multiple_account_targeting",
            "reason": "Multiple accounts targeted from one IP",
        })
    # AUTH-007 Multiple Source Login: 1 user from 3 distinct IPs
    for i, ip in enumerate(["10.100.1.71", "10.100.1.72", "10.100.1.73"]):
        t = (base_time + timedelta(hours=1, minutes=50, seconds=i * 15)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "LOGIN_SUCCESS",
            "event_category": "authentication",
            "source_ip": ip,
            "username": "multi_source_victim",
            "service": "ssh",
            "status": "success",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "suspicious",
            "attack_category": "multiple_source_login",
            "reason": "Same user logging in from multiple sources",
        })
    # WEB-001 Restricted Resource Access: 4 attempts to /admin paths from 10.100.2.1
    for i, path in enumerate(["/admin", "/admin/config", "/admin/users", "/admin/database"]):
        t = (base_time + timedelta(hours=2, seconds=i * 5)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "HTTP_REQUEST",
            "event_category": "web",
            "source_ip": "10.100.2.1",
            "username": "",
            "service": "http",
            "status": "error",
            "http_method": "GET",
            "http_path": path,
            "response_code": 403,
            "label": "suspicious",
            "attack_category": "restricted_resource_access",
            "reason": "Access to restricted admin endpoint",
        })
    # WEB-002 Excessive Request Volume: 6 requests from 10.100.2.2
    for i in range(6):
        t = (base_time + timedelta(hours=2, minutes=10, seconds=i * 2)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "HTTP_REQUEST",
            "event_category": "web",
            "source_ip": "10.100.2.2",
            "username": "",
            "service": "http",
            "status": "success",
            "http_method": "GET",
            "http_path": "/api/stream",
            "response_code": 200,
            "label": "suspicious",
            "attack_category": "excessive_requests",
            "reason": "High rate of HTTP requests",
        })
    # WEB-003 Repeated HTTP 404: 4 requests returning 404 from 10.100.2.3
    for i in range(4):
        t = (base_time + timedelta(hours=2, minutes=20, seconds=i * 5)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "HTTP_REQUEST",
            "event_category": "web",
            "source_ip": "10.100.2.3",
            "username": "",
            "service": "http",
            "status": "error",
            "http_method": "GET",
            "http_path": f"/missing_file_{i}.html",
            "response_code": 404,
            "label": "suspicious",
            "attack_category": "repeated_404",
            "reason": "Directory probing / 404 burst",
        })
    # WEB-004 Repeated HTTP 5xx: 4 requests returning 500 from 10.100.2.4
    for i in range(4):
        t = (base_time + timedelta(hours=2, minutes=30, seconds=i * 5)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "HTTP_REQUEST",
            "event_category": "web",
            "source_ip": "10.100.2.4",
            "username": "",
            "service": "http",
            "status": "error",
            "http_method": "POST",
            "http_path": "/api/submit",
            "response_code": 500,
            "label": "suspicious",
            "attack_category": "repeated_5xx",
            "reason": "Internal server errors caused by payload injection",
        })
    # WEB-005 Sensitive Path Enumeration: 3 requests to /wp-admin, /phpmyadmin, /backup.zip from 10.100.2.5
    for i, path in enumerate(["/wp-admin", "/phpmyadmin", "/backup.zip"]):
        t = (base_time + timedelta(hours=2, minutes=40, seconds=i * 5)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "HTTP_REQUEST",
            "event_category": "web",
            "source_ip": "10.100.2.5",
            "username": "",
            "service": "http",
            "status": "error",
            "http_method": "GET",
            "http_path": path,
            "response_code": 404,
            "label": "suspicious",
            "attack_category": "sensitive_path_enumeration",
            "reason": "Known administrative URL enumeration",
        })
    # FW-001 Repeated Firewall Denials: 4 DENY from 10.100.3.1
    for i in range(4):
        t = (base_time + timedelta(hours=3, seconds=i * 5)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "FIREWALL_EVENT",
            "event_category": "firewall",
            "source_ip": "10.100.3.1",
            "username": "",
            "service": f"tcp/{20+i}",
            "status": "DENY",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "suspicious",
            "attack_category": "firewall_denial_burst",
            "reason": "Port scan connection drops",
        })
    # APP-001 Repeated Application Errors: 4 errors from payment service
    for i in range(4):
        t = (base_time + timedelta(hours=3, minutes=10, seconds=i * 5)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "APP_ERROR",
            "event_category": "application",
            "source_ip": "10.100.4.1",
            "username": "",
            "service": "payment",
            "status": "error",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "suspicious",
            "attack_category": "application_errors",
            "reason": "Repeated application transaction failure",
        })
    # SYS-001 Repeated Service Failures: 4 failures for auditd
    for i in range(4):
        t = (base_time + timedelta(hours=3, minutes=20, seconds=i * 5)).isoformat()
        events.append({
            "timestamp": t,
            "event_type": "SYSTEM_EVENT",
            "event_category": "system",
            "source_ip": "10.100.5.1",
            "username": "",
            "service": "auditd",
            "status": "stopped",
            "http_method": "",
            "http_path": "",
            "response_code": "",
            "label": "suspicious",
            "attack_category": "service_failures",
            "reason": "Security daemon stopped unexpectedly",
        })

    return events


def save_dataset(events):
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "timestamp",
        "event_type",
        "event_category",
        "source_ip",
        "username",
        "service",
        "status",
        "http_method",
        "http_path",
        "response_code",
        "label",
        "attack_category",
        "reason",
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(events)


if __name__ == "__main__":
    dataset = generate_dataset()

    save_dataset(dataset)

    print(f"Generated {len(dataset)} events")
    print(f"Dataset saved to: {OUTPUT_FILE}")
