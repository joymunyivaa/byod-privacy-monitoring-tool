"""
Controlled Traffic Generator for Formal Testing
--------------------------------------------------
Generates a known, fixed number of requests across insecure protocols
(HTTP, FTP, Telnet) and one secure protocol (HTTPS), so that detection
accuracy can be calculated against a known ground truth.

This script does NOT capture or classify anything itself. Run it
WHILE main.py is running and monitoring is active, then compare the
counts it reports against what appears on the dashboard / in the
alerts table.

Usage:
    venv/bin/python3 scripts/generate_test_traffic.py
"""

import subprocess
import time

# Public test endpoints, safe and free to use repeatedly
HTTP_TARGET = "http://neverssl.com"
HTTPS_TARGET = "https://example.com"
FTP_TARGET = "ftp://ftp.gnu.org/"
TELNET_TARGET = "towel.blinkenlights.nl"

# How many times to repeat each request type
HTTP_REQUESTS = 10
HTTPS_REQUESTS = 10
FTP_REQUESTS = 5
TELNET_REQUESTS = 5


def run_http_requests(n):
    print(f"\nSending {n} HTTP requests to {HTTP_TARGET} ...")
    for i in range(n):
        subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "--max-time", "5", HTTP_TARGET],
            check=False
        )
        time.sleep(1)
    print(f"Done: {n} HTTP requests sent.")


def run_https_requests(n):
    print(f"\nSending {n} HTTPS requests to {HTTPS_TARGET} ...")
    for i in range(n):
        subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "--max-time", "5", HTTPS_TARGET],
            check=False
        )
        time.sleep(1)
    print(f"Done: {n} HTTPS requests sent.")


def run_ftp_requests(n):
    print(f"\nSending {n} FTP requests to {FTP_TARGET} ...")
    for i in range(n):
        subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "--max-time", "5", FTP_TARGET],
            check=False
        )
        time.sleep(1)
    print(f"Done: {n} FTP requests sent.")


def run_telnet_requests(n):
    print(f"\nSending {n} Telnet connection attempts to {TELNET_TARGET} ...")
    for i in range(n):
        # -e raises an escape char that immediately closes the session
        subprocess.run(
            ["timeout", "3", "telnet", TELNET_TARGET],
            input="\x1d\n",
            text=True,
            capture_output=True,
            check=False
        )
        time.sleep(1)
    print(f"Done: {n} Telnet connection attempts sent.")


if __name__ == "__main__":
    print("=" * 60)
    print("CONTROLLED TRAFFIC GENERATION FOR ACCURACY TESTING")
    print("=" * 60)
    print(f"\nGround truth expected:")
    print(f"  HTTP (insecure)   : {HTTP_REQUESTS} requests")
    print(f"  FTP (insecure)    : {FTP_REQUESTS} requests")
    print(f"  Telnet (insecure) : {TELNET_REQUESTS} requests")
    print(f"  HTTPS (secure)    : {HTTPS_REQUESTS} requests  <- should NOT alert")
    print(f"\nTotal insecure requests expected: {HTTP_REQUESTS + FTP_REQUESTS + TELNET_REQUESTS}")
    print("\nMake sure main.py is running and monitoring is ACTIVE before continuing.")
    input("Press Enter to begin traffic generation...")

    start_time = time.time()

    run_http_requests(HTTP_REQUESTS)
    run_https_requests(HTTPS_REQUESTS)
    run_ftp_requests(FTP_REQUESTS)
    run_telnet_requests(TELNET_REQUESTS)

    elapsed = time.time() - start_time

    print("\n" + "=" * 60)
    print(f"Traffic generation complete in {elapsed:.2f} seconds.")
    print("Now check the dashboard or query the database directly:")
    print('  sqlite3 data/alerts.db "SELECT protocol, COUNT(*) FROM alerts GROUP BY protocol;"')
    print("=" * 60)
