"""
Author: Sayuni Wimaladharma
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""


import socket
import threading 
import sqlite3
import os
import platform
import datetime

print("Python Version:", platform.python_version())
print("Operating System:", platform.system())


#It is mapping port numbers to their protocol/serivce names.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target


# Q1: What is the benefit of using @property and @target.setter?

#Using @property and @target.setter encapsulates access to the private
# attritubute self.__target, preventing direct external modification. This will
# allow us to add validation logic (like rejecting empty strings) without changing
# how other code accesses the attribute, following the principle of data
# hiding and controlled access in object oriented programming. 

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")

        else:
            self.__target = value

    def __del__(Self):
        print("NetworkTool instance destroyed")

# Q2: How does PortScanner reuse code from NetworkTool?

# PortScanner inherits from NetworkTool and reuses its constructor, property, and destructor
# without rewriting them. The target getter and setter defined in NetworkTool are directly 
# available on PortScanner instances, so self.target works in scan_port() without any extra 
# code in PortScanner.


class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):


# Q3: What would happen without try-except here?

# Without try-except, any network error would raise an unhandled exception and crash the
# entire program mid-scan. Since scan_port runs inside threads, an
# unhandled exception in one thread would also produce confusing tracebacks
# and leave the socket resource open, causing resource leaks.

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            with self.lock:
                self.scan_results.append((port, status, service_name))
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [entry for entry in self.scan_results if entry[1] == "Open"]


#  Q4: Why do we use threading instead of scanning one port at a time?

# Threading allows multiple ports to be scanned at the same time rather than
# waiting for each connection attempt to time out before moving to the next.
# Without threads, scanning 1024 ports with a 1-second timeout each would
# take over 17 minutes. All ports are probed concurrently, completing the 
# scan in roughly the time of a single timeout.

    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute( """
            CREATE TABLE IF NOT EXISTS scans (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                target  TEXT,
                port    INTEGER,
                status  TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)
        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
 
def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT scan_date, target, port, service, status FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                scan_date, target, port, service, status = row
                print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
        conn.close()
    except (sqlite3.Error, sqlite3.OperationalError):
        print("No past scans found.")
 
# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":

    target_ip = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    if target_ip == "":
        target_ip = "127.0.0.1"
 
    start_port = None
    while start_port is None:
        try:
            start_port = int(input("Enter starting port (1-1024): "))
            if not (1 <= start_port <= 1024):
                print("Port must be between 1 and 1024.")
                start_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")
 
    end_port = None
    while end_port is None:
        try:
            end_port = int(input("Enter ending port (1-1024): "))
            if not (1 <= end_port <= 1024):
                print("Port must be between 1 and 1024.")
                end_port = None
            elif end_port < start_port:
                print("End port must be greater than or equal to start port.")
                end_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")
 

    scanner = PortScanner(target_ip)
    print(f"\nScanning {target_ip} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)
 
    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target_ip} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: Open ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")
 
    save_results(target_ip, scanner.scan_results)
 
    view_history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if view_history == "yes":
        load_past_scans()
 

# Q5: New Feature Proposal
# Diagram: See diagram_studentID.png in the repository root

# I would add a service banner-grabbing feature that, after detecting an open port,
# attempts to receive a short response from the service to identify its version. This would use a 
# list comprehension to filter open ports from scan_results and then attempt a recv() on each, 
# with a nested if-statement to only display the banner when non-empty data is actually returned.
