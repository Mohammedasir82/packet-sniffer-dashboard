#!/usr/bin/env python3
import sqlite3
import os
import time
import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP

DEFAULT_DB = "packets_old.db"

def is_valid_sqlite(path: str) -> bool:
    if not os.path.exists(path):
        return False
    try:
        con = sqlite3.connect(path)
        cur = con.execute("PRAGMA quick_check;")
        row = cur.fetchone()
        con.close()
        if row and isinstance(row[0], str) and row[0].lower() == "ok":
            return True
    except sqlite3.DatabaseError:
        return False
    except Exception:
        return False
    return False

def backup_corrupt_db(path: str) -> str:
    ts = time.strftime("%Y%m%d_%H%M%S")
    new = f"{path}.corrupt.{ts}"
    try:
        os.rename(path, new)
        print(f"[DB] Backed up corrupt DB to: {new}")
    except Exception as e:
        print(f"[DB] Failed to rename corrupt DB: {e}")
        try:
            import shutil
            shutil.copy2(path, new)
            print(f"[DB] Copied corrupt DB to: {new}")
            os.remove(path)
        except Exception as ex:
            print(f"[DB] Backup also failed: {ex}")
            raise
    return new

def init_db(path: str) -> sqlite3.Connection:
    if os.path.exists(path) and not is_valid_sqlite(path):
        print(f"[DB] Existing file {path} exists but is not a valid SQLite DB.")
        backup_corrupt_db(path)
    con = sqlite3.connect(path, check_same_thread=False)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            sport INTEGER,
            dport INTEGER,
            length INTEGER
        )
    """)
    con.commit()
    ensure_schema(con)
    return con

def ensure_schema(con: sqlite3.Connection):
    required = {
        "timestamp": "TEXT",
        "src_ip": "TEXT",
        "dst_ip": "TEXT",
        "protocol": "TEXT",
        "sport": "INTEGER",
        "dport": "INTEGER",
        "length": "INTEGER"
    }
    cur = con.cursor()
    cur.execute("PRAGMA table_info(packets);")
    existing = [row[1] for row in cur.fetchall()]
    for col, coltype in required.items():
        if col not in existing:
            try:
                cur.execute(f"ALTER TABLE packets ADD COLUMN {col} {coltype};")
                print(f"[DB] Added missing column: {col} {coltype}")
            except Exception as e:
                print(f"[DB] Could not add column {col}: {e}")
    con.commit()

def insert_packet(con: sqlite3.Connection, timestamp: str, src: str, dst: str,
                  proto: str, sport, dport, length: int):
    try:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, sport, dport, length) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (timestamp, src, dst, proto, sport, dport, length)
        )
        con.commit()
    except Exception as e:
        print(f"[DB ERROR] Insert failed: {e}")

def make_packet_handler(con, src_filters, dst_filters):
    def handle(packet):
        if not packet.haslayer(IP):
            return
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        src = packet[IP].src
        dst = packet[IP].dst
        if src_filters and src not in src_filters:
            return
        if dst_filters and dst not in dst_filters:
            return
        proto = "IP"
        sport = None
        dport = None
        if packet.haslayer(TCP):
            proto = "TCP"
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)
        elif packet.haslayer(ICMP):
            proto = "ICMP"
        length = len(packet)
        insert_packet(con, ts, src, dst, proto, sport, dport, length)
        print(f"{ts} | {src}{(':'+str(sport)) if sport else ''} -> {dst}{(':'+str(dport)) if dport else ''} [{proto}] {length} bytes")
    return handle

def parse_filters(s: str):
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]

def main():
    parser = argparse.ArgumentParser(description="Packet sniffer → SQLite")
    parser.add_argument("--iface", "-i", help="Interface to sniff", default=None)
    parser.add_argument("--bpf", "-f", help="BPF filter", default=None)
    parser.add_argument("--db", "-d", help="Database file", default=DEFAULT_DB)
    parser.add_argument("--src-filter", help="Comma-separated source IPs", default="")
    parser.add_argument("--dst-filter", help="Comma-separated destination IPs", default="")
    args = parser.parse_args()
    src_filters = parse_filters(args.src_filter)
    dst_filters = parse_filters(args.dst_filter)
    print(f"[CONFIG] DB: {args.db}  IFACE: {args.iface or 'default'}  BPF: {args.bpf or 'none'}")
    if src_filters:
        print(f"[CONFIG] Source filters: {src_filters}")
    if dst_filters:
        print(f"[CONFIG] Destination filters: {dst_filters}")
    print("[INFO] Initializing DB...")
    con = init_db(args.db)
    handler = make_packet_handler(con, src_filters, dst_filters)
    print("[INFO] Starting packet capture. Press Ctrl+C to stop.")
    try:
        sniff(prn=handler, iface=args.iface, filter=args.bpf, store=False)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user.")
    except Exception as e:
        print(f"[ERROR] Sniffing failed: {e}")
    finally:
        try:
            con.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
