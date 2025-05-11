#!/usr/bin/env python3
# Filename: kobrakai-v2.py
##################################################################################
#                     ░█░█░█▀█░█▀▄░█▀▄░█▀█░█░█░█▀█░▀█▀░░░█░█░▀▀▄                 #
#                     ░█▀▄░█░█░█▀▄░█▀▄░█▀█░█▀▄░█▀█░░█░░░░▀▄▀░▄▀░                 #
#                     ░▀░▀░▀▀▀░▀▀░░▀░▀░▀░▀░▀░▀░▀░▀░▀▀▀░░░░▀░░▀▀▀                 #
#                                                                                #
##################################################################################
# KOBRAKAI V2 - No Mercy Hacker Blocker for FreePBX Machines - By Pietro Casoar  #
##################################################################################
#                             Version 2.0 (11-05-2025)                           #
##################################################################################

"""
KobraKai v2.0 - Advanced VoIP Security Protection System

This software provides robust protection for FreePBX, Asterisk, and Sangoma VoIP systems against
unauthorized access attempts, brute force attacks, and reconnaissance scans. The system monitors
Asterisk logs in real-time and takes immediate defensive actions against malicious IPs.

KEY FEATURES:
- Real-time monitoring of Asterisk log files for attack signatures
- Immediate blocking of reconnaissance attempts and malformed SIP packets
- First-attempt blocking of suspicious registration attempts
- Rate limiting to prevent connection flooding
- Pattern recognition to identify attack signatures
- Comprehensive IP blocking via iptables with persistent rules
- Resource-efficient operation with minimal system impact
- Configurable security policies via JSON configuration file

UTILITY TOOL:
The accompanying kobrakai-utils.py provides additional functionality:
- IP list analysis and statistics
- Export functionality in various firewall formats
- Testing of regex patterns against log samples
- Ignore list management
- System status monitoring

IMPORTANT SECURITY WARNING:
This software will block ANY unauthorized SIP/IAX registration attempt. To prevent accidental
self-lockout, you MUST add your own IP addresses to the ignore-list.txt file BEFORE running
the software. Use the utility script:
    python3 /home/KobraKai/kobrakai-utils.py ignore --action add --ip YOUR_IP

USAGE:
Standard mode: python3 kobrakai-v2.py
Debug mode:    python3 kobrakai-v2.py --debug
Config file:   python3 kobrakai-v2.py --config /path/to/config.json

CONFIGURATION:
The system is configured via the kobrakai-config.json file, which allows customization of:
- Log file paths and log rotation settings
- Rate limiting thresholds
- Attack pattern definitions and severity levels
- Subnet blocking options
- Advanced detection features

RECOVERY PROCEDURE:
If you accidentally get locked out, you must:
1. Log in locally to the server
2. Edit the "hacker-ips-list.txt" file to remove your IP address
3. Remove the iptables rule: iptables -D INPUT -s YOUR_IP -j DROP
4. Add your IP to the "ignore-list.txt" file

Copyright (c) 2025 FXPRO
This software is provided under an MIT-style license. See README.md for full license details.
"""

# Initiate Modules
import re
import os
import subprocess
import argparse
import time
import json
import datetime
import ipaddress
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import threading
from collections import defaultdict, deque
import gzip
import shutil

# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--debug", help="turn on debug mode", action="store_true")
parser.add_argument("--config", help="path to config file", default="/home/KobraKai/kobrakai-config.json")
args = parser.parse_args()

# Configure the watchdog logging module based on command line argument
if args.debug:
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s [%(levelname)s] %(message)s',
                        filename='/home/KobraKai/kobrakai-debug.log',
                        filemode='a')
else:
    logging.basicConfig(level=logging.ERROR,
                        format='%(asctime)s [%(levelname)s] %(message)s',
                        filename='/home/KobraKai/kobrakai-error.log',
                        filemode='a')

# Load configuration or use defaults
CONFIG = {
    "log_file": "/var/log/asterisk/full",
    "ignore_list_file": "/home/KobraKai/ignore-list.txt",
    "hacker_ips_file": "/home/KobraKai/hacker-ips-list.txt",
    "watch_list_file": "/home/KobraKai/watch-list.json",
    "log_rotation_days": 7,
    "log_max_size_mb": 10,
    "rate_limit_attempts": 3,
    "rate_limit_window": 60,
    "block_subnet_threshold": 5,
    "enable_pattern_recognition": True,
    "enable_rate_limiting": True,
    "enable_subnet_blocking": False,
    "attack_patterns": {
        "severity_high": [
            "PJSIP syntax error",
            "Error processing .* packet from UDP"
        ],
        "severity_medium": [
            "Failed to authenticate",
            "No matching endpoint"
        ],
        "severity_low": [
            "failed for"
        ]
    }
}

# Try to load config file
try:
    if os.path.exists(args.config):
        with open(args.config, 'r') as f:
            user_config = json.load(f)
            CONFIG.update(user_config)
        logging.debug(f"Loaded configuration from {args.config}")
    else:
        # Save default config
        with open(args.config, 'w') as f:
            json.dump(CONFIG, f, indent=4)
        logging.debug(f"Created default configuration at {args.config}")
except Exception as e:
    logging.error(f"Error loading configuration: {e}")

# Set constants from config
ASTERISK_LOG_FILE = CONFIG["log_file"]
IGNORE_LIST_FILE = CONFIG["ignore_list_file"]
HACKER_IPS_LIST_FILE = CONFIG["hacker_ips_file"]
WATCH_LIST_FILE = CONFIG["watch_list_file"]

# Initialize data structures
blocked_ips = set()
watch_list = {}  # IP -> {first_seen, attempt_count, patterns}
rate_tracker = defaultdict(list)  # IP -> list of timestamps
last_processed_position = 0
pattern_memory = defaultdict(int)  # Pattern -> count
latest_scan_ips = deque(maxlen=100)  # Recent IPs that performed scans


def save_iptables():
    """Save the iptables rules to persist across reboots"""
    os.system("iptables-save > /etc/iptables.up.rules")
    logging.debug("iptables rules saved")


def load_iptables():
    """Load the iptables rules"""
    os.system("iptables-restore < /etc/iptables.up.rules")
    logging.debug("iptables rules loaded")


def rotate_logs():
    """Rotate log files to conserve disk space"""
    log_files = [
        '/home/KobraKai/kobrakai-debug.log',
        '/home/KobraKai/kobrakai-error.log'
    ]

    for log_file in log_files:
        if os.path.exists(log_file):
            file_size_mb = os.path.getsize(log_file) / (1024 * 1024)
            if file_size_mb > CONFIG["log_max_size_mb"]:
                timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                backup_file = f"{log_file}.{timestamp}.gz"

                # Compress the log file
                with open(log_file, 'rb') as f_in:
                    with gzip.open(backup_file, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)

                # Clear the original file
                open(log_file, 'w').close()
                logging.debug(f"Rotated log file {log_file} to {backup_file}")

                # Remove old log files
                for old_file in [f for f in os.listdir('/home/KobraKai') if
                                 f.startswith(os.path.basename(log_file)) and f.endswith('.gz')]:
                    file_path = os.path.join('/home/KobraKai', old_file)
                    file_time = os.path.getmtime(file_path)
                    age_days = (time.time() - file_time) / (60 * 60 * 24)
                    if age_days > CONFIG["log_rotation_days"]:
                        os.remove(file_path)
                        logging.debug(f"Removed old log file: {file_path}")


def check_hacker_ips():
    """Verify all hacker IPs are properly blocked in iptables"""
    try:
        with open(HACKER_IPS_LIST_FILE, 'r') as f:
            hacker_ips = set(f.read().splitlines())

        # Get the current iptables rules
        iptables_list = str(subprocess.check_output("iptables -L INPUT -v -n", shell=True))

        for ip in hacker_ips:
            if ip and ip not in iptables_list:
                update_iptables(ip, 'A')
                logging.debug(f"Re-added missing IP block for {ip}")

    except Exception as e:
        logging.error(f"Error checking hacker IPs: {e}")


def update_iptables(ip, action, subnet=False):
    """Update iptables rules to block or unblock an IP or subnet"""
    if not ip:
        return

    try:
        # Determine if this is an IP or subnet
        target = ip
        if subnet:
            # Make sure it's a valid subnet
            try:
                ipaddress.IPv4Network(ip)
            except ValueError:
                logging.error(f"Invalid subnet format: {ip}")
                return

        # Build and execute the command
        cmd = f"iptables -{action} INPUT -s {target} -j DROP"
        logging.info(f"Executing iptables command: {cmd}")

        result = subprocess.run(cmd, shell=True, check=True, capture_output=True)
        logging.debug(f"iptables command result: {result.stdout.decode() if result.stdout else 'Success'}")

        # Save the rules immediately
        save_iptables()

        # If this was a block action, add to blocked_ips
        if action == 'A':
            blocked_ips.add(ip)

    except subprocess.CalledProcessError as e:
        logging.error(f"iptables command failed: {e}")
        if e.stderr:
            logging.error(f"Error details: {e.stderr.decode()}")


def is_valid_ip(ip):
    """Check if the IP address is valid"""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def get_subnet(ip, prefix_length=24):
    """Get the subnet for an IP with specified prefix length"""
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        network = ipaddress.IPv4Network(f"{ip}/{prefix_length}", strict=False)
        return str(network)
    except ValueError:
        logging.error(f"Invalid IP address for subnet calculation: {ip}")
        return None


def block_ip(ip, reason="", severity="low"):
    """Block an IP address and record it with metadata"""
    if not is_valid_ip(ip):
        logging.error(f"Invalid IP address: {ip}")
        return False

    with open(IGNORE_LIST_FILE, 'r') as f:
        ignore_ips = set(f.read().splitlines())

    # Don't block if in ignore list
    if ip in ignore_ips:
        logging.debug(f"IP {ip} in ignore list, not blocking")
        return False

    # Don't block if already blocked
    if ip in blocked_ips:
        logging.debug(f"IP {ip} already blocked")
        return False

    timestamp = datetime.datetime.now().isoformat()

    # Add to hacker list with timestamp
    with open(HACKER_IPS_LIST_FILE, 'a') as f:
        f.write(f"{ip}\n")

    # Update iptables
    update_iptables(ip, 'A')

    # Add IP to blocked set for in-memory tracking
    blocked_ips.add(ip)

    # Remove from watch list if present
    if ip in watch_list:
        del watch_list[ip]
        save_watch_list()

    # Check if we should block the subnet
    if CONFIG["enable_subnet_blocking"]:
        subnet_ips = []
        subnet = get_subnet(ip)
        if subnet:
            # Count how many IPs from this subnet are already blocked
            for blocked_ip in blocked_ips:
                if blocked_ip != ip and get_subnet(blocked_ip) == subnet:
                    subnet_ips.append(blocked_ip)

            # If threshold reached, block the entire subnet
            if len(subnet_ips) >= CONFIG["block_subnet_threshold"]:
                logging.warning(f"Blocking entire subnet {subnet} due to {len(subnet_ips) + 1} malicious IPs")
                update_iptables(subnet, 'A', subnet=True)

    logging.info(f"Blocked IP: {ip} - Reason: {reason} - Severity: {severity}")
    return True


def add_to_watch_list(ip, pattern_detected):
    """Add an IP to the watch list for further monitoring"""
    if ip in blocked_ips or not is_valid_ip(ip):
        return

    now = datetime.datetime.now().isoformat()

    if ip not in watch_list:
        watch_list[ip] = {
            "first_seen": now,
            "last_seen": now,
            "attempt_count": 1,
            "patterns": [pattern_detected]
        }
    else:
        watch_list[ip]["last_seen"] = now
        watch_list[ip]["attempt_count"] += 1
        if pattern_detected not in watch_list[ip]["patterns"]:
            watch_list[ip]["patterns"].append(pattern_detected)

    # Check if this IP should be blocked based on watch list data
    if watch_list[ip]["attempt_count"] >= 3:
        reason = f"Watch list threshold exceeded with patterns: {', '.join(watch_list[ip]['patterns'])}"
        block_ip(ip, reason, "medium")
    else:
        save_watch_list()


def save_watch_list():
    """Save the watch list to disk"""
    try:
        with open(WATCH_LIST_FILE, 'w') as f:
            json.dump(watch_list, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving watch list: {e}")


def load_watch_list():
    """Load the watch list from disk"""
    global watch_list
    try:
        if os.path.exists(WATCH_LIST_FILE):
            with open(WATCH_LIST_FILE, 'r') as f:
                watch_list = json.load(f)

            # Clean up old entries
            now = datetime.datetime.now()
            to_remove = []
            for ip, data in watch_list.items():
                last_seen = datetime.datetime.fromisoformat(data["last_seen"])
                age_hours = (now - last_seen).total_seconds() / 3600
                if age_hours > 24:  # Remove entries older than 24 hours
                    to_remove.append(ip)

            for ip in to_remove:
                del watch_list[ip]

            if to_remove:
                save_watch_list()
    except Exception as e:
        logging.error(f"Error loading watch list: {e}")
        watch_list = {}


def check_rate_limit(ip):
    """Check if an IP has exceeded the rate limit"""
    if not CONFIG["enable_rate_limiting"]:
        return False

    now = time.time()
    rate_tracker[ip].append(now)

    # Remove timestamps older than the window
    rate_tracker[ip] = [t for t in rate_tracker[ip] if now - t <= CONFIG["rate_limit_window"]]

    # Check if rate limit exceeded
    return len(rate_tracker[ip]) > CONFIG["rate_limit_attempts"]


def process_log_line(line):
    """Process a log line to detect and block attacks"""
    global latest_scan_ips

    # Skip empty lines
    if not line.strip():
        return

    # Pattern detection - first extract IP address with any method
    ip_patterns = [
        r"failed for '(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
        r"from UDP (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
        r"failed for '(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):",
        r"from '(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):"
    ]

    ip = None
    for pattern in ip_patterns:
        match = re.search(pattern, line)
        if match:
            ip = match.group(1)
            if is_valid_ip(ip):
                break

    if not ip:
        return

    # Don't process if already blocked
    if ip in blocked_ips:
        return

    # Check against ignore list
    with open(IGNORE_LIST_FILE, 'r') as f:
        ignore_ips = set(f.read().splitlines())
    if ip in ignore_ips:
        return

    # Check for high severity patterns - block immediately
    for pattern in CONFIG["attack_patterns"]["severity_high"]:
        if re.search(pattern, line):
            logging.warning(f"High severity attack detected from {ip}: {pattern}")
            block_ip(ip, f"High severity pattern: {pattern}", "high")
            latest_scan_ips.append(ip)
            return

    # Check for medium severity patterns - may block immediately or add to watch list
    for pattern in CONFIG["attack_patterns"]["severity_medium"]:
        if re.search(pattern, line):
            # Check if this IP was recently seen in a scan
            if ip in latest_scan_ips:
                logging.warning(f"Medium severity attack from recent scanning IP {ip}: {pattern}")
                block_ip(ip, f"Medium severity after scan: {pattern}", "medium")
                return

            # Check rate limiting
            if check_rate_limit(ip):
                logging.warning(f"Rate limit exceeded for {ip}")
                block_ip(ip, f"Rate limit exceeded with pattern: {pattern}", "medium")
                return

            # Add to watch list
            add_to_watch_list(ip, pattern)
            logging.info(f"Added to watch list: {ip} - Pattern: {pattern}")
            return

    # Check for low severity patterns - add to watch list
    for pattern in CONFIG["attack_patterns"]["severity_low"]:
        if re.search(pattern, line):
            add_to_watch_list(ip, pattern)
            logging.debug(f"Low severity pattern from {ip}: {pattern}")
            return


class AsteriskLogHandler(FileSystemEventHandler):
    """Handler for file system events on the Asterisk log file"""

    def on_modified(self, event):
        global last_processed_position

        if event.src_path == ASTERISK_LOG_FILE:
            try:
                with open(event.src_path, 'r', encoding='latin-1') as f:
                    # Seek to the last processed position
                    f.seek(last_processed_position)

                    # Read new lines
                    new_lines = f.readlines()

                    # Save new position
                    last_processed_position = f.tell()

                    # Process new lines
                    for line in new_lines:
                        process_log_line(line)

            except Exception as e:
                logging.error(f"Error processing log file: {e}")
                # Reset position on error
                last_processed_position = 0


def cleanup_thread():
    """Background thread to clean up old data and rotate logs"""
    while True:
        try:
            # Rotate logs if needed
            rotate_logs()

            # Check and clean watch list
            now = datetime.datetime.now()
            to_remove = []

            for ip, data in watch_list.items():
                last_seen = datetime.datetime.fromisoformat(data["last_seen"])
                age_hours = (now - last_seen).total_seconds() / 3600
                if age_hours > 24:  # Remove entries older than 24 hours
                    to_remove.append(ip)

            for ip in to_remove:
                del watch_list[ip]

            if to_remove:
                save_watch_list()
                logging.debug(f"Removed {len(to_remove)} old entries from watch list")

            # Clear old rate limiting data
            now_time = time.time()
            for ip in list(rate_tracker.keys()):
                # Remove timestamps older than the window
                rate_tracker[ip] = [t for t in rate_tracker[ip] if now_time - t <= CONFIG["rate_limit_window"]]
                # Remove IPs with no recent activity
                if not rate_tracker[ip]:
                    del rate_tracker[ip]

        except Exception as e:
            logging.error(f"Error in cleanup thread: {e}")

        # Sleep for 1 hour
        time.sleep(3600)


def export_ip_list(output_file=None):
    """Export the list of blocked IPs in a format suitable for firewall import"""
    if not output_file:
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        output_file = f"/home/KobraKai/blocked_ips_{timestamp}.txt"

    try:
        with open(HACKER_IPS_LIST_FILE, 'r') as f:
            ips = [line.strip() for line in f if line.strip() and is_valid_ip(line.strip())]

        with open(output_file, 'w') as f:
            for ip in sorted(ips):
                f.write(f"{ip}\n")

        logging.info(f"Exported {len(ips)} blocked IPs to {output_file}")
        return output_file
    except Exception as e:
        logging.error(f"Error exporting IP list: {e}")
        return None


def initialize():
    """Initialize the application state"""
    global blocked_ips, last_processed_position

    try:
        # Create directories if they don't exist
        os.makedirs(os.path.dirname(HACKER_IPS_LIST_FILE), exist_ok=True)

        # Create files if they don't exist
        for file_path in [HACKER_IPS_LIST_FILE, IGNORE_LIST_FILE]:
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    pass
                logging.info(f"Created empty file: {file_path}")

        # Load blocked IPs
        with open(HACKER_IPS_LIST_FILE, 'r') as f:
            blocked_ips = set(line.strip() for line in f if line.strip())

        # Load watch list
        load_watch_list()

        # Find the current size of the log file
        if os.path.exists(ASTERISK_LOG_FILE):
            last_processed_position = os.path.getsize(ASTERISK_LOG_FILE)

        logging.info(
            f"Initialization complete. {len(blocked_ips)} IPs in block list, {len(watch_list)} IPs in watch list")

    except Exception as e:
        logging.error(f"Error during initialization: {e}")
        raise


if __name__ == "__main__":
    print("Starting KobraKai v2.0 - No Mercy Hacker Blocker")
    print(f"Log level: {'DEBUG' if args.debug else 'ERROR'}")

    try:
        # Initialize the system
        initialize()

        # Load and verify iptables rules
        load_iptables()
        check_hacker_ips()

        # Start the cleanup thread
        cleanup = threading.Thread(target=cleanup_thread, daemon=True)
        cleanup.start()

        # Set up the file system observer
        event_handler = AsteriskLogHandler()
        observer = Observer()
        observer.schedule(event_handler, path=os.path.dirname(ASTERISK_LOG_FILE), recursive=False)
        observer.start()

        print("KobraKai is now running. Press Ctrl+C to stop.")

        # Main loop
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping KobraKai...")
        observer.stop()
        observer.join()
        save_watch_list()
        print("KobraKai stopped.")
    except Exception as e:
        logging.critical(f"Critical error: {e}")
        print(f"Critical error: {e}")
        raise

# END OF CODE
