import subprocess
import sqlite3
import re
import time
from datetime import datetime
from collections import defaultdict, deque

DB = "/tmp/netra_events.db"
conn = sqlite3.connect(DB, check_same_thread=False)

conn.execute("""
CREATE TABLE IF NOT EXISTS events (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT, source TEXT, destination TEXT,
event_type TEXT, details TEXT)
""")

conn.execute("""
CREATE TABLE IF NOT EXISTS alerts (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT, source TEXT, destination TEXT,
alert_type TEXT, severity TEXT, details TEXT)
""")
conn.commit()

ports = defaultdict(deque)
pings = defaultdict(deque)
hosts = defaultdict(deque)

def save(ts, src, dst, kind, details):
    conn.execute(
        "INSERT INTO events(timestamp,source,destination,event_type,details) VALUES(?,?,?,?,?)",
        (ts, src, dst, kind, details)
    )
    conn.commit()

def alert(ts, src, dst, kind, severity, details):
    conn.execute(
        "INSERT INTO alerts(timestamp,source,destination,alert_type,severity,details) VALUES(?,?,?,?,?,?)",
        (ts, src, dst, kind, severity, details)
    )
    conn.commit()
    print(f"[ALERT] {kind}: {src} -> {dst} | {details}", flush=True)

print("NETRA detection engine running!", flush=True)

cmd = [
    "tcpdump", "-l", "-n", "-tt", "-i", "any",
    "tcp[tcpflags] & tcp-syn != 0 or icmp[icmptype] = icmp-echo"
]

proc = subprocess.Popen(
    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    text=True, bufsize=1
)

for line in proc.stdout:
    tcp = re.search(
        r"(\d+\.\d+) IP ([\d.]+)\.(\d+) > ([\d.]+)\.(\d+): Flags \[S",
        line
    )
    icmp = re.search(
        r"(\d+\.\d+) IP ([\d.]+) > ([\d.]+): ICMP echo request",
        line
    )

    if not tcp and not icmp:
        continue

    now = time.time()
    ts = datetime.now().isoformat(timespec="seconds")

    if tcp:
        _, src, sport, dst, dport = tcp.groups()
        save(ts, src, dst, "TCP SYN", f"Port {dport}")

        q = ports[(src, dst)]
        q.append((now, dport))
        while q and now - q[0][0] > 10:
            q.popleft()

        count = len(set(port for _, port in q))
        if count >= 8:
            alert(ts, src, dst, "PORT SCAN", "HIGH",
                  f"{count} distinct ports in 10 seconds")

    elif icmp:
        _, src, dst = icmp.groups()
        save(ts, src, dst, "ICMP PING", "Echo request")

        q = hosts[src]
        q.append((now, dst))
        while q and now - q[0][0] > 10:
            q.popleft()

        count = len(set(ip for _, ip in q))
        if count >= 5:
            alert(ts, src, "Multiple devices", "HOST DISCOVERY",
                  "MEDIUM", f"{count} devices pinged in 10 seconds")

        p = pings[(src, dst)]
        p.append(now)
        while p and now - p[0] > 10:
            p.popleft()

        if len(p) >= 10:
            alert(ts, src, dst, "HIGH PING RATE", "MEDIUM",
                  f"{len(p)} pings in 10 seconds")
