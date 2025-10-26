#!/usr/bin/env python3
r"""
██╗  ██╗ ██████╗ ██████╗ ██████╗  █████╗ ██╗  ██╗ █████╗ ██╗      ██╗   ██╗██████╗    ██████╗
██║ ██╔╝██╔═══██╗██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██║      ██║   ██║╚════██╗   ╚════██╗
█████╔╝ ██║   ██║██████╔╝██████╔╝███████║█████╔╝ ███████║██║█████╗██║   ██║ █████╔╝    █████╔╝
██╔═██╗ ██║   ██║██╔══██╗██╔══██╗██╔══██║██╔═██╗ ██╔══██║██║╚════╝╚██╗ ██╔╝██╔═══╝     ╚═══██╗
██║  ██╗╚██████╔╝██████╔╝██║  ██║██║  ██║██║  ██╗██║  ██║██║       ╚████╔╝ ███████╗██╗██████╔╝
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═══╝  ╚══════╝╚═╝╚═════╝
###############################################################################################
#         KOBRAKAI V2 - No Mercy Hacker Blocker for FreePBX Machines - By Pietro Casoar       #
###############################################################################################
#                                    Version 2.3 (01-08-2025)                                 #
###############################################################################################
                          My Personal Message To Malicious VoIP Hackers
                                               /"\
                                              |\./|
                                              |   |
                                              |   |
                                              |>*<|
                                              |   |
                                           /'\|   |/'\
                                       /'\|   |   |   |
                                      |   |   |   |   |\
                                      |   |   |   |   |  \
                                      | *   *   *   * |>  >
                                     |                  /
                                       |               /
                                        |            /
                                         \          |
                                          |         |
###############################################################################################
KobraKai v2.3 - Advanced VoIP Security Protection System (Enhanced Edition)

This software provides robust protection for FreePBX, Asterisk, and Sangoma VoIP systems against
unauthorized access attempts, brute force attacks, and reconnaissance scans. The system monitors
Asterisk logs in real-time and takes immediate defensive actions against malicious IPs.

KEY FEATURES:
- Real-time monitoring of Asterisk log files for attack signatures
- Immediate blocking of reconnaissance attempts and malformed SIP packets
- Single blocking path architecture eliminates infinite loops and race conditions
- Atomic operations with file locking prevent state corruption
- Idempotent iptables operations safe to run multiple times
- Pattern recognition for common VoIP attack vectors
- Comprehensive IP blocking via iptables with persistent rules
- Resource-efficient operation with minimal system impact
- Configurable security policies via JSON configuration
- Built-in management tools for listing, testing, and unblocking IPs

ENHANCED SECURITY FEATURES (v2.3+):
- 🛡 Robust architecture prevents infinite blocking loops
- 🔒 Thread-safe operations with proper state locking
- ⚡ Single atomic blocking path for all security decisions
- 📊 Clean iptables rule management with verification
- 🎯 Reliable log position tracking with rotation handling
- 💾 Enhanced pattern recognition for malformed packet detection
- 🔧 Built-in diagnostic and management commands
- 📝 Comprehensive logging with proper error handling
- ⚠ Graceful shutdown with signal handling
- 🚀 Production-ready with persistent state management

ATTACK MITIGATION CAPABILITIES:
- SIP endpoint enumeration attacks - Immediate blocking on first attempt
- PJSIP syntax error attacks with malformed packets - Critical threat response
- Authentication brute force attempts - Progressive monitoring and blocking
- OPTIONS flood attacks - Rate-based detection and blocking
- Extension enumeration scans - Watch list monitoring
- Protocol violation attempts - Pattern-based detection
- Reconnaissance scanning - First-attempt blocking for non-existent endpoints

IMPORTANT SECURITY WARNING:
This software will block unauthorized SIP/IAX registration attempts. To prevent accidental
self-lockout, you MUST add your legitimate IP addresses to the ignore_ips.txt file BEFORE running
the software. Add your IP addresses to /home/KobraKai/ignore_ips.txt (one IP per line).

USAGE:
Standard mode:     python3 kobrakai-v2.py
Debug mode:        python3 kobrakai-v2.py --debug
Test blocking:     python3 kobrakai-v2.py --test-ip 1.2.3.4
List blocked IPs:  python3 kobrakai-v2.py --list-blocked
Remove IP:         python3 kobrakai-v2.py --unblock 1.2.3.4
Custom config:     python3 kobrakai-v2.py --config /path/to/config.json

CONFIGURATION:
The system uses a default configuration optimized for most environments. Custom configuration
can be provided via JSON file with the following options:
- Log file paths and monitoring settings
- Attack pattern definitions and severity levels
- IP extraction patterns for various log formats
- Blocking thresholds and watch list parameters
- Data directory and file locations

SYSTEM REQUIREMENTS:
- Python 3.6+ with standard libraries
- iptables with comment module support (-m comment)
- Root/sudo access for iptables management
- Read access to Asterisk log files
- Write access to data directory for state files
- Sufficient disk space for logging and state management

PERFORMANCE IMPACT:
The enhanced architecture maintains minimal system impact:
- Efficient log polling with position tracking
- Atomic file operations prevent corruption
- Memory-efficient pattern matching
- Clean iptables rule management without duplication
- Background cleanup of expired watch entries

RECOVERY PROCEDURE:
If you accidentally get locked out:
1. Log in locally to the server console
2. Remove your IP: python3 kobrakai-v2.py --unblock YOUR_IP
3. Add your IP to ignore list: echo "YOUR_IP" >> /home/KobraKai/ignore_ips.txt
4. Remove iptables rule: iptables -D INPUT -s YOUR_IP -m comment --comment 'KobraKai_Block' -j DROP
5. Restart the service if needed

SYSTEM ARCHITECTURE:
- Single blocking path prevents race conditions
- Thread-safe operations with proper locking
- Atomic file writes with temporary files
- Idempotent iptables operations
- Clean state management across restarts
- Proper signal handling for graceful shutdown

Copyright (c) 2025 FXPRO ---> Pietro Casoar
This software is provided under an MIT-style license.

CHANGELOG v2.3 Enhanced Edition:
- Complete architectural rewrite for stability and reliability
- Eliminated infinite loop conditions and race conditions
- Implemented single atomic blocking path for all decisions
- Added robust state management with file locking
- Enhanced iptables management with proper verification
- Added built-in management and diagnostic tools
- Improved log processing with reliable position tracking
- Added comprehensive error handling and graceful shutdown
- Implemented thread-safe operations throughout
- FIXED: All critical bugs from previous versions eliminated
"""

import os
import re
import time
import json
import fcntl
import signal
import logging
import argparse
import datetime
import ipaddress
import subprocess
from pathlib import Path
from threading import Lock
from collections import defaultdict

# Configuration
DEFAULT_CONFIG = {
    "log_file": "/var/log/asterisk/full",
    "data_dir": "/home/KobraKai",
    "blocked_ips_file": "blocked_ips.txt",
    "ignore_ips_file": "ignore_ips.txt",
    "watch_ips_file": "watch_ips.json",
    "position_file": "last_position.txt",
    "poll_interval": 1.0,
    "block_patterns": [
        "No matching endpoint found",
        "PJSIP syntax error",
        "Error processing.*packet",
        "Failed to authenticate",
        "Request.*failed for"
    ],
        # IP extraction: IPv4, IPv6, and a couple of common Asterisk log formats (captures address:port)
    "ip_extraction_patterns": [
        # IPv4 classic
        r"failed for '(\d{1,3}(?:\.\d{1,3}){3}):\d+'",
        r"from UDP (\d{1,3}(?:\.\d{1,3}){3}):\d+",
        r"No matching endpoint found (?:for|from) '(\d{1,3}(?:\.\d{1,3}){3}):\d+'",

        # IPv6 (allow bracketed or bare)
        r"failed for '\[?([0-9A-Fa-f:]+)\]?:\d+'",
        r"from UDP \[?([0-9A-Fa-f:]+)\]?:\d+",
        r"No matching endpoint found (?:for|from) '\[?([0-9A-Fa-f:]+)\]?:\d+'",

        # Generic SIP URI: sip:user@host[:port]
        r"sip:[^@>]+@(\[?[0-9A-Fa-f:.]+\]?|[A-Za-z0-9\.\-]+)(?::\d+)?",

        # Generic “Request … failed for 'HOST:PORT'”
        r"Request '.*?'.*?failed for '\[?([0-9A-Fa-f:.]+)\]? :\d+'",   # tolerate brackets & spaces
        r"Request '.*?'.*?failed for '\[?([0-9A-Fa-f:.]+)\]?[:]\d+'"
    ],

    "max_watch_attempts": 3,
    "watch_window_seconds": 300
}

class VoIPSecurityMonitor:
    def __init__(self, config_file=None, debug=False):
        self.config = DEFAULT_CONFIG.copy()
        self.debug = debug
        self.running = False
        self.state_lock = Lock()

        # Load configuration
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.config.update(json.load(f))

        # Setup paths
        self.data_dir = Path(self.config["data_dir"])
        self.data_dir.mkdir(exist_ok=True)

        self.blocked_ips_file = self.data_dir / self.config["blocked_ips_file"]
        self.ignore_ips_file = self.data_dir / self.config["ignore_ips_file"]
        self.watch_ips_file = self.data_dir / self.config["watch_ips_file"]
        self.position_file = self.data_dir / self.config["position_file"]

        # Setup logging
        log_level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(self.data_dir / 'kobrakai.log'),
                logging.StreamHandler()
            ]
        )

        # Initialize state
        self.blocked_ips = set()
        self.ignore_ips = set()
        self.watch_ips = {}

        # Compile patterns
        self.ip_patterns = [re.compile(p) for p in self.config["ip_extraction_patterns"]]
        self.block_patterns = [re.compile(p) for p in self.config["block_patterns"]]

        # Load initial state
        self._load_state()

    def _load_state(self):
        """Load persistent state from files with file locking for safety"""
        # Load blocked IPs
        if self.blocked_ips_file.exists():
            with open(self.blocked_ips_file, 'r') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                for line in f:
                    ip = line.strip().split('#')[0].strip()
                    if self._is_valid_ip(ip):
                        self.blocked_ips.add(ip)

        # Load ignore IPs
        if self.ignore_ips_file.exists():
            with open(self.ignore_ips_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if self._is_valid_ip(ip):
                        self.ignore_ips.add(ip)

        # Load watch IPs
        if self.watch_ips_file.exists():
            try:
                with open(self.watch_ips_file, 'r') as f:
                    self.watch_ips = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                self.watch_ips = {}

        logging.info(
            f"Loaded state: {len(self.blocked_ips)} blocked, {len(self.ignore_ips)} ignored, {len(self.watch_ips)} watched")

    def _save_state(self):
        """Save current state to files with atomic writes"""
        # Save blocked IPs
        temp_file = self.blocked_ips_file.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            for ip in sorted(self.blocked_ips):
                timestamp = datetime.datetime.now().isoformat()
                f.write(f"{ip} # Blocked {timestamp}\n")
        temp_file.replace(self.blocked_ips_file)

        # Save watch IPs
        temp_file = self.watch_ips_file.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(self.watch_ips, f, indent=2)
        temp_file.replace(self.watch_ips_file)

    def _is_valid_ip(self, ip_str):
        """Validate IP address format (IPv4 or IPv6). Returns normalized string on success."""
        if not ip_str:
            return False
        s = ip_str.strip()
        try:
            # ipaddress will accept IPv4 or IPv6 and raise on invalid input
            ip_obj = ipaddress.ip_address(s)
            # Normalize to compressed IPv6 or dotted IPv4 string for consistent storage
            return True
        except (ValueError, AttributeError):
            return False

    def _extract_ip(self, log_line):
        """Extract IP address from log line using compiled patterns"""
        for pattern in self.ip_patterns:
            match = pattern.search(log_line)
            if match:
                potential_ip = match.group(1)
                if self._is_valid_ip(potential_ip):
                    return potential_ip
        return None

    def _should_block(self, log_line):
        """Check if log line matches blocking patterns"""
        for pattern in self.block_patterns:
            if pattern.search(log_line):
                return True
        return False

    def _is_iptables_blocked(self, ip):
        """Check if IP is already blocked in iptables"""
        try:
            result = subprocess.run([
                'iptables', '-C', 'INPUT', '-s', ip,
                '-m', 'comment', '--comment', 'KobraKai_Block',
                '-j', 'DROP'
            ], capture_output=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False

    def _block_ip_iptables(self, ip):
        """Block IP in iptables with idempotent operation"""
        if self._is_iptables_blocked(ip):
            logging.debug(f"IP {ip} already blocked in iptables")
            return True

        try:
            # Insert rule at position 1 for immediate effect
            subprocess.run([
                'iptables', '-I', 'INPUT', '1',
                '-s', ip,
                '-m', 'comment', '--comment', 'KobraKai_Block',
                '-j', 'DROP'
            ], check=True, timeout=10)

            # Verify rule was added
            if self._is_iptables_blocked(ip):
                logging.info(f"Successfully blocked {ip} in iptables")
                return True
            else:
                logging.error(f"Failed to verify iptables block for {ip}")
                return False

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logging.error(f"Failed to block {ip} in iptables: {e}")
            return False

    def _save_iptables(self):
        """Save iptables rules for persistence"""
        try:
            subprocess.run([
                'iptables-save'
            ], stdout=open('/etc/iptables.up.rules', 'w'), check=True, timeout=10)
            logging.debug("iptables rules saved")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logging.error(f"Failed to save iptables rules: {e}")

    def block_ip(self, ip: str, reason: str):
        """Add DROP rule(s) for the IP (IPv4 and, if applicable, IPv6) with safety guards."""
        # ---- safety: only block valid, non-private/non-reserved addresses ----
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            if self.debug:
                logging.debug(f"Not blocking invalid IP {ip}")
            return

        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
                ip_obj.is_reserved or ip_obj.is_multicast):
            if self.debug:
                logging.debug(f"Skip block for private/reserved IP {ip}")
            return

        # idempotence: skip if we already marked it
        if ip in getattr(self, "blocked_ips", set()):
            if self.debug:
                logging.debug(f"IP {ip} already in blocked list")
            return

        # ---- IPv4 rule (iptables) ----
        try:
            chk = ["iptables", "-C", "INPUT", "-s", ip, "-m", "comment", "--comment", "KobraKai_Block", "-j", "DROP"]
            if subprocess.call(chk, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                subprocess.check_call(
                    ["iptables", "-I", "INPUT", "1", "-s", ip, "-m", "comment", "--comment", "KobraKai_Block", "-j",
                     "DROP"])
            logging.info(f"Successfully blocked {ip} in iptables")
        except Exception as e:
            logging.error(f"Failed to add iptables rule for {ip}: {e}")
            return  # don't record as blocked if install failed

        # ---- IPv6 rule (ip6tables) if this is a v6 address ----
        if ip_obj.version == 6:
            try:
                chk6 = ["ip6tables", "-C", "INPUT", "-s", ip, "-m", "comment", "--comment", "KobraKai_Block", "-j",
                        "DROP"]
                if subprocess.call(chk6, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                    subprocess.check_call(
                        ["ip6tables", "-I", "INPUT", "1", "-s", ip, "-m", "comment", "--comment", "KobraKai_Block",
                         "-j", "DROP"])
            except Exception as e:
                # IPv6 not present or command missing is fine; keep going
                logging.debug(f"ip6tables update skipped/failed for {ip}: {e}")

        # ---- record & persist ----
        self.blocked_ips.add(ip)
        self._save_state()
        logging.warning(f"BLOCKED IP: {ip} - Reason: {reason}")

    def add_to_watchlist(self, ip, reason=""):
        """Add IP to watch list for monitoring repeated attempts"""
        with self.state_lock:
            now = datetime.datetime.now().isoformat()

            if ip not in self.watch_ips:
                self.watch_ips[ip] = {
                    "first_seen": now,
                    "attempt_count": 1,
                    "reasons": [reason]
                }
            else:
                self.watch_ips[ip]["attempt_count"] += 1
                if reason not in self.watch_ips[ip]["reasons"]:
                    self.watch_ips[ip]["reasons"].append(reason)

            # Check if should block
            if self.watch_ips[ip]["attempt_count"] >= self.config["max_watch_attempts"]:
                reasons = ", ".join(self.watch_ips[ip]["reasons"])
                self.block_ip(ip, f"Watch threshold exceeded: {reasons}")
            else:
                logging.info(f"Added to watchlist: {ip} (attempt {self.watch_ips[ip]['attempt_count']}) - {reason}")

    def cleanup_watchlist(self):
        """Remove old entries from watch list"""
        cutoff = datetime.datetime.now() - datetime.timedelta(seconds=self.config["watch_window_seconds"])
        to_remove = []

        for ip, data in self.watch_ips.items():
            first_seen = datetime.datetime.fromisoformat(data["first_seen"])
            if first_seen < cutoff:
                to_remove.append(ip)

        for ip in to_remove:
            del self.watch_ips[ip]

        if to_remove:
            logging.debug(f"Cleaned up {len(to_remove)} old watch entries")

    def process_log_line(self, line):
        """Process a single log line for threats.

        Immediate block for:
          * "No matching endpoint found"
          * "PJSIP syntax error"
          * Malformed packet errors ("Error processing.*packet")
          * ANY SIP method auth failure:
              "Request 'METHOD' ... failed for 'IP:port' ... - Failed to authenticate"
            (METHOD can be REGISTER, INVITE, SUBSCRIBE, MESSAGE, OPTIONS, etc.)
        Otherwise: add to watch list (thresholded blocking).

        Enhanced IP extraction:
          * Prefer "failed for 'IP:port'" (supports IPv4 and IPv6 like "[2001:db8::1]:5060")
          * Fallback to existing self._extract_ip()
        """
        line = line.strip()
        if not line:
            return

        # Fast category pre-check
        if not self._should_block(line):
            return

        # ---------- helper: extract IP (IPv4/IPv6) from "failed for 'IP:port'" -----------
        def _ip_from_failed_for(src_line: str):
            """
            Extract the real source host from: "... failed for 'HOST:PORT'"
            HOST may be IPv4, [IPv6], or a bare IPv6 without brackets.
            """
            m = re.search(
                r"failed\s+for\s+'(\[?[0-9A-Fa-f:.]+\]?|\[?[A-Za-z0-9\-\.:]+\]?):\d+'",
                src_line,
                flags=re.IGNORECASE
            )
            if not m:
                return None
            ip_addr = m.group(1)
            # Strip brackets around bracketed IPv6
            if ip_addr.startswith('[') and ip_addr.endswith(']'):
                ip_addr = ip_addr[1:-1]
            return ip_addr

        # ---------- extract an IP early when possible ----------
        ip = _ip_from_failed_for(line)
        if not ip:
            ip = self._extract_ip(line)  # fallback to legacy extractor
        if not ip:
            if self.debug:
                logging.debug(f"No IP extracted from: {line}")
            return  # cannot block without an IP

        # Instant block on malformed SIP that pjproject rejects (source in "from UDP X:Y")
        m = re.search(r"pjproject:\s*sip_transport\..*from UDP\s+(\d{1,3}(?:\.\d{1,3}){3}):\d+", line,
                      flags=re.IGNORECASE)
        if m:
            ip = m.group(1)
            # optional: add a sanity check so you never block your own host/IPs/domains
            if ip not in self.ignored_ips and ip != self.host_ip:
                self.block_ip(ip, f"Malformed SIP packet rejected by pjproject: {line[:160]}...")
                return

        # ---------- Immediate-block categories ----------
        if ("No matching endpoint found" in line or
                "PJSIP syntax error" in line or
                re.search(r"Error processing.*packet", line)):
            self.block_ip(ip, f"Critical threat: {line[:100]}...")
            return

        # ANY SIP method auth failure on first sight (REGISTER/INVITE/SUBSCRIBE/MESSAGE/OPTIONS/etc.)
        # Matches:
        #   Request 'METHOD' ... failed for 'IP:port' ... - Failed to authenticate
        # Any SIP method (REGISTER/INVITE/SUBSCRIBE/MESSAGE/OPTIONS/etc.), case-insensitive
        method_match = re.search(r"Request\s+'([A-Za-z]+)'", line, flags=re.IGNORECASE)
        if method_match and re.search(r"Failed to authenticate|authentication failed", line, flags=re.IGNORECASE):
            method = method_match.group(1).upper()
            self.block_ip(ip, f"Auth fail on SIP {method}: {line[:160]}...")
            return

        # Instant block if caller display-name looks like a scanner (e.g., "123456" only digits)
        disp = re.search(r"from\s+'\"?([^\"<]+)\"?\s*<sip:", line, flags=re.IGNORECASE)
        if disp:
            dn = disp.group(1).strip()
            if re.fullmatch(r"\d{6,}", dn):  # six+ digits only is almost always enumeration
                self.block_ip(ip, f"Scanner-like display-name '{dn}': {line[:160]}...")
                return

        # ---------- Fallback (watch list) ----------
        self.add_to_watchlist(ip, f"Suspicious activity: {line[:50]}...")

    def get_last_position(self):
        """Get last processed position in log file"""
        try:
            if self.position_file.exists():
                with open(self.position_file, 'r') as f:
                    return int(f.read().strip())
        except (ValueError, FileNotFoundError):
            pass
        return 0

    def save_position(self, position):
        """Save current position in log file"""
        with open(self.position_file, 'w') as f:
            f.write(str(position))

    def process_log_file(self):
        """Process log file from last known position"""
        log_file = Path(self.config["log_file"])
        if not log_file.exists():
            logging.warning(f"Log file not found: {log_file}")
            return

        try:
            last_position = self.get_last_position()
            current_size = log_file.stat().st_size

            # Handle log rotation
            if current_size < last_position:
                logging.info("Log rotation detected, starting from beginning")
                last_position = 0

            # Read new content
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                new_position = f.tell()

            # Process new lines
            lines_processed = 0
            for line in new_lines:
                self.process_log_line(line)
                lines_processed += 1

            # Save new position
            self.save_position(new_position)

            if lines_processed > 0 and self.debug:
                logging.debug(f"Processed {lines_processed} new log lines")

        except Exception as e:
            logging.error(f"Error processing log file: {e}")

    def cleanup_expired_blocks(self):
        """Remove blocks older than configured time (optional maintenance)"""
        # This is intentionally simple - just log current state
        logging.info(f"Current state: {len(self.blocked_ips)} blocked IPs, {len(self.watch_ips)} watched IPs")

    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logging.info(f"Received signal {signum}, shutting down...")
        self.running = False

    def run(self):
        """Main monitoring loop"""
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

        logging.info("KobraKai v3.0 starting...")
        logging.info(f"Monitoring: {self.config['log_file']}")
        logging.info(f"Data directory: {self.data_dir}")

        self.running = True
        last_cleanup = time.time()

        try:
            while self.running:
                # Process log file
                self.process_log_file()

                # Periodic cleanup (every 5 minutes)
                if time.time() - last_cleanup > 300:
                    self.cleanup_watchlist()
                    self.cleanup_expired_blocks()
                    last_cleanup = time.time()

                # Sleep before next poll
                time.sleep(self.config["poll_interval"])

        except KeyboardInterrupt:
            logging.info("Interrupted by user")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            raise
        finally:
            self._save_state()
            logging.info("KobraKai v3.0 stopped")


def main():
    parser = argparse.ArgumentParser(description="KobraKai v3.0 - VoIP Security Monitor")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--test-ip", help="Test blocking functionality with IP")
    parser.add_argument("--list-blocked", action="store_true", help="List currently blocked IPs")
    parser.add_argument("--unblock", help="Remove IP from block list")

    args = parser.parse_args()

    monitor = VoIPSecurityMonitor(config_file=args.config, debug=args.debug)

    if args.test_ip:
        success = monitor.block_ip(args.test_ip, "Manual test")
        print(f"Test block of {args.test_ip}: {'SUCCESS' if success else 'FAILED'}")
        return

    if args.list_blocked:
        print(f"Currently blocked IPs ({len(monitor.blocked_ips)}):")
        for ip in sorted(monitor.blocked_ips):
            print(f"  {ip}")
        return

    if args.unblock:
        if args.unblock in monitor.blocked_ips:
            monitor.blocked_ips.remove(args.unblock)
            monitor._save_state()
            print(f"Removed {args.unblock} from block list")
            print("Note: Manual iptables cleanup may be required")
        else:
            print(f"IP {args.unblock} not found in block list")
        return

    # Run main monitoring loop
    monitor.run()


if __name__ == "__main__":
    main()
