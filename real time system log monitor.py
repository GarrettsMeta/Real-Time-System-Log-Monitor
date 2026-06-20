import os
import re
import time
import sqlite3
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

# Configuration Placeholders for Freelance Clients
LOG_FILE_PATH = "server_simulation.log"
DB_FILE_PATH = "alert_history.db"
ALERT_EMAIL_SENDER = "monitor@clientdomain.com"
ALERT_EMAIL_RECEIVER = "admin@clientdomain.com"
SMTP_SERVER = "localhost"
SMTP_PORT = 1025

# Rate Limiting Controls
ALERT_WINDOW_SECONDS = 60
MAX_ALERTS_PER_WINDOW = 3
alert_timestamps = []

# Vulnerability / Threat Signatures
SUSPICIOUS_PATTERNS = {
    "CRITICAL": re.compile(r"(failed login|permission denied|unauthorized access|invalid token)", re.IGNORECASE),
    "WARNING": re.compile(r"(disk space low|high memory utility|connection dropped)", re.IGNORECASE)
}


def init_database():
    """Initializes high-integrity ledger for tracking past security incidents."""
    conn = sqlite3.connect(DB_FILE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_alert_to_db(severity, message):
    """Persists alert entries inside the local relational database."""
    conn = sqlite3.connect(DB_FILE_PATH)
    cursor = conn.cursor()
    now_str = datetime.now().isoformat()
    cursor.execute(
        "INSERT INTO security_alerts (timestamp, severity, message) VALUES (?, ?, ?)",
        (now_str, severity, message)
    )
    conn.commit()
    conn.close()
    print(f"[*] Database record written: [{severity}] {message}")


def check_rate_limit():
    """Evaluates if outbound communication thresholds have been breached."""
    global alert_timestamps
    now = time.time()
    # Prune historical stamps out of the current window
    alert_timestamps = [
        t for t in alert_timestamps if now - t < ALERT_WINDOW_SECONDS]

    if len(alert_timestamps) >= MAX_ALERTS_PER_WINDOW:
        return False  # Rate limit triggered, suppress dispatch

    alert_timestamps.append(now)
    return True


def send_email_alert(severity, message):
    """Dispatches instant email communication via client configuration schemas."""
    if not check_rate_limit():
        print(
            f"[!] Rate limit active. Alert notification suppressed: [{severity}]")
        return

    msg = MIMEText(
        f"Security Alert Triggered:\n\nSeverity: {severity}\nDetails: {message}\nTimestamp: {datetime.now()}")
    msg['Subject'] = f"[{severity} ALERT] System Log Monitor Notification"
    msg['From'] = ALERT_EMAIL_SENDER
    msg['To'] = ALERT_EMAIL_RECEIVER

    print(f"[+] Outbound Email Alert Sent to {ALERT_EMAIL_RECEIVER}")
    # Under deployment, uncomment the live transport logic:
    # try:
    #     with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
    #         server.send_message(msg)
    # except Exception as e:
    #     print(f"[-] Email delivery failed: {e}")


def process_log_line(line):
    """Parses raw text strings looking for security pattern signatures."""
    cleaned_line = line.strip()
    if not cleaned_line:
        return

    for severity, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(cleaned_line):
            log_alert_to_db(severity, cleaned_line)
            send_email_alert(severity, cleaned_line)
            break


def tail_log_file():
    """Continuously monitors log streams for new structural line inputs."""
    print(f"[*] Starting Real-Time Log Engine on: {LOG_FILE_PATH}")
    if not os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, 'w') as f:
            f.write("--- Log Engine Initialization ---\n")

    with open(LOG_FILE_PATH, 'r') as f:
        # Move file cursor position instantly to end of file to read only live events
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)  # Free up CPU execution cycles
                continue
            process_log_line(line)


if __name__ == "__main__":
    init_database()
    # Generates simulated logs for immediate out-of-the-box local sandbox verification
    print("[*] Generating active testing logs...")
    with open(LOG_FILE_PATH, 'a') as test_log:
        test_log.write("INFO: System normal boot sequences running.\n")
        test_log.write(
            "WARNING: disk space low on block root storage /dev/sda1\n")
        test_log.write(
            "CRITICAL: failed login attempt from remote interface 192.168.1.45\n")

    # Run the continuous log checking engine
    try:
        tail_log_file()
    except KeyboardInterrupt:
        print("\n[*] Log monitor gracefully terminating.")
