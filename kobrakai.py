#!/usr/bin/env python3
r"""
██╗  ██╗ ██████╗ ██████╗ ██████╗  █████╗ ██╗  ██╗ █████╗ ██╗
██║ ██╔╝██╔═══██╗██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██║
█████╔╝ ██║   ██║██████╔╝██████╔╝███████║█████╔╝ ███████║██║
██╔═██╗ ██║   ██║██╔══██╗██╔══██╗██╔══██║██╔═██╗ ██╔══██║██║
██║  ██╗╚██████╔╝██████╔╝██║  ██║██║  ██║██║  ██╗██║  ██║██║
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
#####################################################################
#    KOBRAKAI - No Mercy VoIP Hacker Blocker for FreePBX/Asterisk   #
#####################################################################
#                        Version 1.0.0                              #
#####################################################################
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
#####################################################################
KobraKai - Advanced VoIP Security Protection System

FEATURES:
- Real-time monitoring of Asterisk log files for attack signatures
- Geo-Blocking with country whitelist (MaxMind GeoLite2 database)
- Complete IPv6 SIP blocking (protects SIP ports while preserving web access)
- Honeypot extension protection with auto-detection from Asterisk
- Rate limiting with burst and slow-scan detection
- User-Agent fingerprinting and scanner detection
- Sequential extension scanning detection
- SIP method abuse detection (OPTIONS floods, abnormal usage)
- Authentication timing analysis (rapid retries, auth storms)
- Call duration anomaly detection (fraud patterns)
- Attack pattern learning with auto-adaptation
- Immediate blocking of reconnaissance attempts and malformed SIP packets
- Pattern recognition for common VoIP attack vectors
- Comprehensive IP blocking via iptables with persistent rules

ATTACK MITIGATION CAPABILITIES:
- SIP endpoint enumeration attacks
- PJSIP syntax error attacks with malformed packets
- Authentication brute force attempts
- OPTIONS flood attacks
- Extension enumeration scans
- Protocol violation attempts
- Reconnaissance scanning
- IPv6 reconnaissance
- Geographic attacks
- Rate-based attacks (burst and slow-scan)
- Scanner tools (User-Agent fingerprinting)
- SIP method abuse
- Timing-based attacks
- Fraud patterns

IMPORTANT SECURITY WARNING:
This software will block unauthorized SIP/IAX registration attempts. To prevent
accidental self-lockout, you MUST add your legitimate IP addresses to the
ignore_ips.txt file BEFORE running the software.

USAGE:
Standard mode:              python3 kobrakai.py
Debug mode:                 python3 kobrakai.py --debug
Test blocking:              python3 kobrakai.py --test-ip 1.2.3.4
List blocked IPs:           python3 kobrakai.py --list-blocked
Remove IP:                  python3 kobrakai.py --unblock 1.2.3.4
Show extensions:            python3 kobrakai.py --show-extensions
Refresh extensions:         python3 kobrakai.py --refresh-extensions
Test extension:             python3 kobrakai.py --test-extension 9999
Show learned patterns:      python3 kobrakai.py --show-learned-patterns
Show behavior analysis:     python3 kobrakai.py --show-behavior IP
Cleanup duplicates:         python3 kobrakai.py --cleanup
Custom config:              python3 kobrakai.py --config /path/to/config.json

SYSTEM REQUIREMENTS:
- Python 3.6+ with standard libraries
- geoip2 library (pip install geoip2) - for geo-blocking
- iptables with comment module support (-m comment)
- Root/sudo access for iptables management
- Read access to Asterisk log files
- Read access to /etc/asterisk/ (for extension auto-detection)
- Write access to data directory for state files

Copyright (c) 2025 Pietro Casoar
This software is provided under the MIT License.
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
from collections import defaultdict, deque

# Try to import geoip2 for geo-blocking
try:
    import geoip2.database
    import geoip2.errors

    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# Configuration
DEFAULT_CONFIG = {
    "log_file": "/var/log/asterisk/full",
    "data_dir": "/opt/kobrakai",
    "blocked_ips_file": "blocked_ips.txt",
    "ignore_ips_file": "ignore_ips.txt",
    "watch_ips_file": "watch_ips.json",
    "position_file": "last_position.txt",
    "poll_interval": 0.1,

    # Geo-blocking settings
    "geoip_enabled": False,
    "geoip_database": "/opt/kobrakai/geoip/GeoLite2-Country.mmdb",
    "allowed_countries": ["AU"],  # ISO 3166-1 alpha-2 codes - CHANGE THIS TO YOUR COUNTRY

    # IPv6 blocking settings
    "block_all_ipv6": True,

    # Honeypot extension protection
    "honeypot_enabled": True,
    "extensions_file": "/opt/kobrakai/extensions.json",
    "auto_detect_extensions": True,
    "extension_refresh_interval": 3600,  # seconds

    # Rate limiting settings
    "max_requests_per_minute": 20,
    "max_requests_per_hour": 200,
    "burst_threshold": 5,
    "burst_window_seconds": 3,
    "slow_scan_threshold": 100,
    "slow_scan_window_hours": 6,

    # Pattern learning settings
    "learning_mode": True,
    "learned_patterns_file": "learned_patterns.json",
    "auto_block_threshold": 80,  # severity score 0-100
    "pattern_cleanup_days": 30,

    # User-Agent fingerprinting settings
    "useragent_detection_enabled": True,
    "scanner_useragents": [
        "friendly-scanner",
        "sipvicious",
        "sipcli",
        "pplsip",
        "sundayddr",
        "iWar",
        "sipsak",
        "VaxSIPUserAgent",
        "sip-scan",
        "smap",
        "sipv",
        "scanner",
        "test",
        "nmap",
        "masscan",
        "sipp",
        "voipmonitor",
        "asterisk pbx",
        "exosip",
        "oSIP",
        "openser",
        "kamailio",
        "freeswitch"
    ],

    # Sequential extension scanning settings
    "sequential_scan_enabled": True,
    "sequential_scan_window": 300,  # seconds
    "sequential_scan_threshold": 5,  # number of sequential extensions

    # SIP method abuse settings
    "method_abuse_enabled": True,
    "method_abuse_threshold": 5,
    "method_abuse_window": 10,  # seconds

    # Authentication timing settings
    "auth_timing_enabled": True,
    "auth_retry_minimum_seconds": 1,
    "auth_storm_threshold": 3,
    "auth_storm_window": 5,  # seconds

    # Call duration anomaly settings
    "call_duration_enabled": True,
    "suspicious_call_duration_max": 5,  # seconds
    "suspicious_call_count_threshold": 10,

    "block_patterns": [
        "No matching endpoint found",
        "PJSIP syntax error",
        "Error processing.*packet",
        "Failed to authenticate",
        "Request.*failed for",
        "Forbidden",
        "Unauthorized",
        "Security event",
        "Invalid.*request",
        "ACL.*reject",
        "flood.*detect",
        "malformed",
        "Bad request",
        "Not found",
        "auth.*reject"
    ],

    # IP extraction patterns
    "ip_extraction_patterns": [
        r"failed for '(\d{1,3}(?:\.\d{1,3}){3}):\d+'",
        r"from UDP (\d{1,3}(?:\.\d{1,3}){3}):\d+",
        r"No matching endpoint found (?:for|from) '(\d{1,3}(?:\.\d{1,3}){3}):\d+'",
        r"failed for '\[?([0-9A-Fa-f:]+)\]?:\d+'",
        r"from UDP \[?([0-9A-Fa-f:]+)\]?:\d+",
        r"No matching endpoint found (?:for|from) '\[?([0-9A-Fa-f:]+)\]?:\d+'",
    ],

    # Watchlist settings
    "max_watch_attempts": 3,
    "watch_window_seconds": 300,

    # Whitelist networks - NEVER block these (CIDR notation)
    # Add your internal networks here!
    "whitelist_networks": [
        "127.0.0.0/8",        # Localhost - ALWAYS keep this
        # "10.0.0.0/8",       # Example: Private network Class A
        # "172.16.0.0/12",    # Example: Private network Class B
        # "192.168.0.0/16",   # Example: Private network Class C
    ],
}


class VoIPSecurityMonitor:
    def __init__(self, config_file=None, debug=False):
        self.debug = debug
        self.config = DEFAULT_CONFIG.copy()

        # Load custom config if provided
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    custom_config = json.load(f)
                    self.config.update(custom_config)
                    logging.info(f"Loaded custom configuration from {config_file}")
            except Exception as e:
                logging.error(f"Error loading config file: {e}, using defaults")

        # Initialize data directory first (needed for logging)
        self.data_dir = Path(self.config["data_dir"])
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Setup logging - write to file directly with explicit handler
        log_level = logging.DEBUG if debug else logging.INFO
        log_file = self.data_dir / "kobrakai.log"

        # Clear any existing handlers and force our configuration
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)

        # Remove existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # Add file handler
        file_handler = logging.FileHandler(str(log_file), mode='a')
        file_handler.setLevel(log_level)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

        # File paths
        self.blocked_ips_file = self.data_dir / self.config["blocked_ips_file"]
        self.ignore_ips_file = self.data_dir / self.config["ignore_ips_file"]
        self.watch_ips_file = self.data_dir / self.config["watch_ips_file"]
        self.position_file = self.data_dir / self.config["position_file"]

        # Additional file paths
        self.extensions_file = Path(self.config["extensions_file"])
        self.learned_patterns_file = self.data_dir / self.config["learned_patterns_file"]

        # Initialize state
        self.blocked_ips = set()
        self.ignore_ips = set()
        self.watch_ips = {}
        self.host_ip = self._get_host_ip()
        self.lock = Lock()
        self.running = False

        # Rate limiting data
        self.rate_data = defaultdict(lambda: {
            'timestamps': [],
            'minute_count': 0,
            'hour_count': 0,
            'last_reset_minute': time.time(),
            'last_reset_hour': time.time()
        })

        # Extension protection data
        self.valid_extensions = set()
        self.extension_patterns = []
        self.extension_ranges = []

        # Pattern learning data
        self.learned_patterns = {}

        # GeoIP reader
        self.geoip_reader = None

        # Behavioral analysis data structures
        self.behavior_data = defaultdict(lambda: {
            'user_agents': [],
            'extension_attempts': deque(maxlen=100),
            'sip_methods': defaultdict(list),
            'auth_attempts': [],
            'call_durations': []
        })

        # Load state
        self._load_state()

        # Initialize geo-blocking
        self._init_geoip()

        # Load extensions if honeypot enabled
        if self.config['honeypot_enabled']:
            self._load_extensions()

        # Load learned patterns
        if self.config['learning_mode']:
            self._load_learned_patterns()

        # Setup IPv6 blocking
        if self.config['block_all_ipv6']:
            self._setup_ipv6_blocking()

        # Log startup status
        logging.info(f"Geo-blocking: {'ENABLED' if self.config['geoip_enabled'] and self.geoip_reader else 'DISABLED'}")
        logging.info(f"IPv6 blocking: {'ENABLED' if self.config['block_all_ipv6'] else 'DISABLED'}")
        logging.info(
            f"Honeypot protection: {'ENABLED' if self.config['honeypot_enabled'] else 'DISABLED'} ({len(self.valid_extensions)} extensions)")
        logging.info(f"Pattern learning: {'ENABLED' if self.config['learning_mode'] else 'DISABLED'}")
        logging.info(f"User-Agent detection: {'ENABLED' if self.config['useragent_detection_enabled'] else 'DISABLED'}")
        logging.info(
            f"Sequential scan detection: {'ENABLED' if self.config['sequential_scan_enabled'] else 'DISABLED'}")
        logging.info(f"SIP method abuse detection: {'ENABLED' if self.config['method_abuse_enabled'] else 'DISABLED'}")
        logging.info(f"Auth timing analysis: {'ENABLED' if self.config['auth_timing_enabled'] else 'DISABLED'}")
        logging.info(f"Call duration analysis: {'ENABLED' if self.config['call_duration_enabled'] else 'DISABLED'}")

    def _init_geoip(self):
        """Initialize GeoIP database for geo-blocking"""
        if not self.config['geoip_enabled']:
            return

        if not GEOIP_AVAILABLE:
            logging.warning("GeoIP blocking enabled but geoip2 library not installed. Install: pip install geoip2")
            self.config['geoip_enabled'] = False
            return

        geoip_db_path = Path(self.config['geoip_database'])
        if not geoip_db_path.exists():
            logging.warning(f"GeoIP database not found: {geoip_db_path}")
            logging.warning("Geo-blocking disabled. Run geoip/download-geoip.sh to download database.")
            self.config['geoip_enabled'] = False
            return

        try:
            self.geoip_reader = geoip2.database.Reader(str(geoip_db_path))
            logging.info(f"GeoIP database loaded: {geoip_db_path}")
        except Exception as e:
            logging.error(f"Failed to load GeoIP database: {e}")
            self.config['geoip_enabled'] = False

    def _setup_ipv6_blocking(self):
        """Setup IPv6 blocking via ip6tables - ONLY for SIP ports, not all traffic"""
        # Block SIP-related ports only to avoid breaking web services
        sip_ports = [5060, 5061, 5160, 5161, 10000, 20000]

        for port in sip_ports:
            try:
                # Check if rule already exists for this port (UDP)
                check_cmd = ["ip6tables", "-C", "INPUT", "-p", "udp", "--dport", str(port), "-j", "DROP"]
                result = subprocess.run(check_cmd, capture_output=True, text=True)

                if result.returncode != 0:
                    # Rule doesn't exist, add it
                    block_cmd = ["ip6tables", "-I", "INPUT", "-p", "udp", "--dport", str(port), "-j", "DROP",
                                "-m", "comment", "--comment", "KobraKai: IPv6 SIP block"]
                    subprocess.run(block_cmd, check=True, capture_output=True)
                    logging.debug(f"IPv6 blocking rule added for UDP port {port}")

                # Also block TCP for signaling ports
                if port in [5060, 5061, 5160, 5161]:
                    check_cmd_tcp = ["ip6tables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"]
                    result_tcp = subprocess.run(check_cmd_tcp, capture_output=True, text=True)

                    if result_tcp.returncode != 0:
                        block_cmd_tcp = ["ip6tables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP",
                                        "-m", "comment", "--comment", "KobraKai: IPv6 SIP block"]
                        subprocess.run(block_cmd_tcp, check=True, capture_output=True)
                        logging.debug(f"IPv6 blocking rule added for TCP port {port}")

            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to setup IPv6 blocking for port {port}: {e}")
            except Exception as e:
                logging.error(f"Error setting up IPv6 blocking for port {port}: {e}")

        logging.info("IPv6 SIP port blocking configured (web services preserved)")

    def _check_geolocation(self, ip):
        """Check if IP is from allowed country. Returns (allowed, country_code)"""
        if not self.config['geoip_enabled'] or not self.geoip_reader:
            return True, None

        try:
            response = self.geoip_reader.country(ip)
            country_code = response.country.iso_code

            if country_code in self.config['allowed_countries']:
                return True, country_code
            else:
                return False, country_code

        except geoip2.errors.AddressNotFoundError:
            logging.debug(f"IP {ip} not found in GeoIP database")
            return True, None  # Allow if not found
        except Exception as e:
            logging.error(f"GeoIP lookup error for {ip}: {e}")
            return True, None  # Allow on error

    def _load_extensions(self):
        """Load valid extensions from file and/or auto-detection"""
        # Try auto-detection first
        if self.config['auto_detect_extensions']:
            detected = self._auto_detect_extensions()
            if detected:
                self.valid_extensions.update(detected)
                logging.info(f"Auto-detected {len(detected)} extensions from Asterisk")

        # Load from extensions.json
        if self.extensions_file.exists():
            try:
                with open(self.extensions_file, 'r') as f:
                    ext_config = json.load(f)

                # Load exact extensions
                if 'extensions' in ext_config:
                    self.valid_extensions.update(ext_config['extensions'])

                # Load patterns
                if 'extension_patterns' in ext_config:
                    for pattern in ext_config['extension_patterns']:
                        self.extension_patterns.append(re.compile(pattern))

                # Load ranges
                if 'extension_ranges' in ext_config:
                    self.extension_ranges = ext_config['extension_ranges']

                logging.info(f"Loaded extensions from {self.extensions_file}")
                logging.info(
                    f"Total: {len(self.valid_extensions)} exact, {len(self.extension_patterns)} patterns, {len(self.extension_ranges)} ranges")

            except Exception as e:
                logging.error(f"Error loading extensions file: {e}")
        else:
            # Create template file
            self._create_extensions_template()

        # Validate we have at least some extensions
        if not self.valid_extensions and not self.extension_patterns and not self.extension_ranges:
            logging.warning(
                "Honeypot enabled but no extensions configured! Create extensions.json or enable auto-detection")

    def _auto_detect_extensions(self):
        """Auto-detect extensions from Asterisk configuration"""
        detected = set()

        # Method 1: Query PJSIP endpoints
        try:
            result = subprocess.run(
                ["asterisk", "-rx", "pjsip show endpoints"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    match = re.match(r'^(\d+)\s+', line)
                    if match:
                        detected.add(match.group(1))
        except Exception as e:
            logging.debug(f"PJSIP endpoint query failed: {e}")

        # Method 2: Parse pjsip.conf files
        pjsip_files = ['/etc/asterisk/pjsip.conf', '/etc/asterisk/pjsip_custom.conf']
        for conf_file in pjsip_files:
            try:
                if os.path.exists(conf_file):
                    with open(conf_file, 'r') as f:
                        for line in f:
                            match = re.match(r'^\[(\d+)\]', line)
                            if match:
                                detected.add(match.group(1))
            except Exception as e:
                logging.debug(f"Error parsing {conf_file}: {e}")

        # Method 3: Parse extensions.conf
        ext_files = ['/etc/asterisk/extensions.conf', '/etc/asterisk/extensions_custom.conf']
        for conf_file in ext_files:
            try:
                if os.path.exists(conf_file):
                    with open(conf_file, 'r') as f:
                        for line in f:
                            match = re.match(r'^\s*exten\s*=>\s*(\d+),', line)
                            if match:
                                ext = match.group(1)
                                if ext not in ['s', 'h', 't', 'i']:  # Skip special extensions
                                    detected.add(ext)
            except Exception as e:
                logging.debug(f"Error parsing {conf_file}: {e}")

        return detected

    def _create_extensions_template(self):
        """Create template extensions.json file"""
        template = {
            "extensions": [],
            "extension_patterns": [],
            "extension_ranges": [],
            "comments": [
                "INSTRUCTIONS:",
                "1. Add exact extensions to 'extensions' array: ['100', '101', '102']",
                "2. Add regex patterns to 'extension_patterns': ['1[0-9]{2}'] matches 100-199",
                "3. Add ranges to 'extension_ranges': ['100-150'] matches 100 through 150",
                "4. After configuring, set honeypot_enabled: true in main config",
                "5. Run: python3 kobrakai.py --show-extensions to verify"
            ]
        }

        try:
            with open(self.extensions_file, 'w') as f:
                json.dump(template, f, indent=2)
            logging.info(f"Created template extensions file: {self.extensions_file}")
        except Exception as e:
            logging.error(f"Error creating extensions template: {e}")

    def _is_valid_extension(self, extension):
        """Check if extension is valid (exact, pattern, or range match)"""
        # Check exact match
        if extension in self.valid_extensions:
            return True

        # Check pattern match
        for pattern in self.extension_patterns:
            if pattern.match(extension):
                return True

        # Check range match
        try:
            ext_num = int(extension)
            for range_str in self.extension_ranges:
                if '-' in range_str:
                    start, end = map(int, range_str.split('-'))
                    if start <= ext_num <= end:
                        return True
        except ValueError:
            pass

        return False

    def _extract_extension(self, log_line):
        """Extract attempted extension from SIP messages"""
        # Pattern 1: INVITE sip:extension@domain
        match = re.search(r'INVITE sip:(\d+)@', log_line)
        if match:
            return match.group(1)

        # Pattern 2: To: <sip:extension@domain>
        match = re.search(r'To: <sip:(\d+)@', log_line)
        if match:
            return match.group(1)

        # Pattern 3: Request-URI: sip:extension@domain
        match = re.search(r'Request-URI: sip:(\d+)@', log_line)
        if match:
            return match.group(1)

        # Pattern 4: REGISTER from '"extension" <sip:extension@...>'
        match = re.search(r'REGISTER.*from\s+["\'](\d+)["\']', log_line, re.IGNORECASE)
        if match:
            return match.group(1)

        # Pattern 5: from '"extension" <sip:...'
        match = re.search(r'from\s+["\'](\d+)["\']?\s*<sip:', log_line, re.IGNORECASE)
        if match:
            return match.group(1)

        # Pattern 6: <sip:extension@domain> in any context
        match = re.search(r'<sip:(\d+)@', log_line)
        if match:
            return match.group(1)

        return None

    def _load_learned_patterns(self):
        """Load learned patterns from file"""
        if self.learned_patterns_file.exists():
            try:
                with open(self.learned_patterns_file, 'r') as f:
                    self.learned_patterns = json.load(f)
                logging.info(f"Loaded {len(self.learned_patterns)} learned patterns")
            except Exception as e:
                logging.error(f"Error loading learned patterns: {e}")

    def _save_learned_patterns(self):
        """Save learned patterns to file"""
        try:
            with open(self.learned_patterns_file, 'w') as f:
                json.dump(self.learned_patterns, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving learned patterns: {e}")

    def _update_learned_pattern(self, pattern_signature, ip):
        """Update or create learned pattern entry"""
        now = datetime.datetime.now().isoformat()

        if pattern_signature not in self.learned_patterns:
            self.learned_patterns[pattern_signature] = {
                'count': 0,
                'severity': 0,
                'first_seen': now,
                'last_seen': now,
                'blocked_ips': [],
                'auto_blocked': False
            }

        pattern = self.learned_patterns[pattern_signature]
        pattern['count'] += 1
        pattern['last_seen'] = now

        if ip not in pattern['blocked_ips']:
            pattern['blocked_ips'].append(ip)

        # Calculate severity (0-100) based on count and unique IPs
        pattern['severity'] = min(100, (pattern['count'] * 2) + (len(pattern['blocked_ips']) * 5))

        # Auto-block if severity threshold reached
        if pattern['severity'] >= self.config['auto_block_threshold'] and not pattern['auto_blocked']:
            pattern['auto_blocked'] = True
            logging.info(
                f"Pattern auto-blocked (severity {pattern['severity']}): {pattern_signature[:100]}")

    def _check_rate_limit(self, ip):
        """Check if IP has exceeded rate limits. Returns violation reason or None"""
        now = time.time()
        rate = self.rate_data[ip]

        # Add current timestamp
        rate['timestamps'].append(now)

        # Cleanup old timestamps (older than 6 hours for slow-scan)
        cutoff = now - (self.config['slow_scan_window_hours'] * 3600)
        rate['timestamps'] = [ts for ts in rate['timestamps'] if ts > cutoff]

        # Check burst detection
        burst_cutoff = now - self.config['burst_window_seconds']
        burst_count = sum(1 for ts in rate['timestamps'] if ts > burst_cutoff)
        if burst_count >= self.config['burst_threshold']:
            return f"Burst threshold exceeded: {burst_count} requests in {self.config['burst_window_seconds']} seconds"

        # Check per-minute rate
        minute_cutoff = now - 60
        minute_count = sum(1 for ts in rate['timestamps'] if ts > minute_cutoff)
        if minute_count >= self.config['max_requests_per_minute']:
            return f"Per-minute rate exceeded: {minute_count} requests/minute"

        # Check per-hour rate
        hour_cutoff = now - 3600
        hour_count = sum(1 for ts in rate['timestamps'] if ts > hour_cutoff)
        if hour_count >= self.config['max_requests_per_hour']:
            return f"Per-hour rate exceeded: {hour_count} requests/hour"

        # Check slow-scan detection
        slow_scan_cutoff = now - (self.config['slow_scan_window_hours'] * 3600)
        slow_scan_count = sum(1 for ts in rate['timestamps'] if ts > slow_scan_cutoff)
        if slow_scan_count >= self.config['slow_scan_threshold']:
            return f"Slow-scan detected: {slow_scan_count} requests in {self.config['slow_scan_window_hours']} hours"

        return None

    # User-Agent Detection Methods

    def _extract_user_agent(self, log_line):
        """Extract User-Agent string from SIP message"""
        match = re.search(r'User-Agent:\s*(.+?)(?:\r|\n|$)', log_line, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    def _check_user_agent(self, ip, user_agent):
        """Check User-Agent for scanner patterns. Returns violation reason or None"""
        if not self.config['useragent_detection_enabled']:
            return None

        if not user_agent:
            return None

        # Track User-Agent
        behavior = self.behavior_data[ip]
        if user_agent not in behavior['user_agents']:
            behavior['user_agents'].append(user_agent)

        # Check for scanner patterns
        ua_lower = user_agent.lower()
        for scanner_pattern in self.config['scanner_useragents']:
            if scanner_pattern.lower() in ua_lower:
                return f"Scanner User-Agent detected: {user_agent}"

        # Check for empty or suspicious User-Agent
        if len(user_agent) < 3:
            return f"Suspicious empty User-Agent: {user_agent}"

        return None

    # Sequential Extension Scanning Detection

    def _check_sequential_scan(self, ip, extension):
        """Detect sequential extension scanning patterns. Returns violation reason or None"""
        if not self.config['sequential_scan_enabled']:
            return None

        if not extension:
            return None

        now = time.time()
        behavior = self.behavior_data[ip]

        # Add extension attempt with timestamp
        behavior['extension_attempts'].append({
            'extension': extension,
            'timestamp': now
        })

        # Filter attempts within window
        window_cutoff = now - self.config['sequential_scan_window']
        recent_attempts = [
            att for att in behavior['extension_attempts']
            if att['timestamp'] > window_cutoff
        ]

        if len(recent_attempts) < self.config['sequential_scan_threshold']:
            return None

        # Extract extension numbers
        try:
            extension_numbers = []
            for att in recent_attempts[-10:]:  # Check last 10 attempts
                try:
                    ext_num = int(att['extension'])
                    extension_numbers.append(ext_num)
                except ValueError:
                    pass

            if len(extension_numbers) < self.config['sequential_scan_threshold']:
                return None

            # Check for sequential patterns
            # Pattern 1: Incremental (1000, 1001, 1002, 1003...)
            is_sequential = True
            for i in range(1, len(extension_numbers)):
                if extension_numbers[i] != extension_numbers[i - 1] + 1:
                    is_sequential = False
                    break

            if is_sequential:
                return f"Sequential extension scan detected: {extension_numbers[-5:]}"

            # Pattern 2: Decremental (5000, 4999, 4998...)
            is_decremental = True
            for i in range(1, len(extension_numbers)):
                if extension_numbers[i] != extension_numbers[i - 1] - 1:
                    is_decremental = False
                    break

            if is_decremental:
                return f"Sequential extension scan detected (reverse): {extension_numbers[-5:]}"

            # Pattern 3: Jump patterns (1000, 2000, 3000... or 1000, 1100, 1200...)
            if len(extension_numbers) >= 3:
                differences = [extension_numbers[i] - extension_numbers[i - 1] for i in
                               range(1, len(extension_numbers))]
                if len(set(differences)) == 1 and differences[0] > 0:
                    return f"Jump pattern scan detected (step={differences[0]}): {extension_numbers[-5:]}"

        except Exception as e:
            logging.debug(f"Error in sequential scan detection: {e}")

        return None

    # SIP Method Abuse Detection

    def _extract_sip_method(self, log_line):
        """Extract SIP method from log line"""
        match = re.search(
            r'\b(INVITE|REGISTER|OPTIONS|SUBSCRIBE|NOTIFY|ACK|BYE|CANCEL|REFER|INFO|UPDATE|PRACK|MESSAGE)\b', log_line)
        if match:
            return match.group(1)
        return None

    def _check_sip_method_abuse(self, ip, method):
        """Detect SIP method abuse patterns. Returns violation reason or None"""
        if not self.config['method_abuse_enabled']:
            return None

        if not method:
            return None

        now = time.time()
        behavior = self.behavior_data[ip]

        # Track method with timestamp
        behavior['sip_methods'][method].append(now)

        # Cleanup old timestamps
        window_cutoff = now - self.config['method_abuse_window']
        behavior['sip_methods'][method] = [
            ts for ts in behavior['sip_methods'][method]
            if ts > window_cutoff
        ]

        # Check for OPTIONS flood (scanner behavior)
        if method == 'OPTIONS':
            options_count = len(behavior['sip_methods']['OPTIONS'])
            if options_count >= self.config['method_abuse_threshold']:
                return f"OPTIONS flood detected: {options_count} requests in {self.config['method_abuse_window']}s"

        # Check for abnormal method patterns
        if method == 'SUBSCRIBE':
            register_count = len(behavior['sip_methods'].get('REGISTER', []))
            subscribe_count = len(behavior['sip_methods']['SUBSCRIBE'])
            if subscribe_count > 5 and register_count == 0:
                return f"SUBSCRIBE without REGISTER (abnormal): {subscribe_count} SUBSCRIBE, 0 REGISTER"

        # Excessive NOTIFY without context
        if method == 'NOTIFY':
            notify_count = len(behavior['sip_methods']['NOTIFY'])
            if notify_count >= 20:
                return f"Excessive NOTIFY: {notify_count} requests"

        return None

    # Authentication Timing Analysis

    def _check_auth_timing(self, ip, log_line):
        """Analyze authentication attempt timing. Returns violation reason or None"""
        if not self.config['auth_timing_enabled']:
            return None

        # Check if this is an auth failure
        if not re.search(r'(Failed to authenticate|authentication.*failed)', log_line, re.IGNORECASE):
            return None

        now = time.time()
        behavior = self.behavior_data[ip]

        # Track auth attempt
        behavior['auth_attempts'].append(now)

        # Cleanup old attempts
        window_cutoff = now - self.config['auth_storm_window']
        behavior['auth_attempts'] = [
            ts for ts in behavior['auth_attempts']
            if ts > window_cutoff
        ]

        # Check for auth storm
        if len(behavior['auth_attempts']) >= self.config['auth_storm_threshold']:
            return f"Authentication storm: {len(behavior['auth_attempts'])} attempts in {self.config['auth_storm_window']}s"

        # Check for rapid retry (too fast between attempts)
        if len(behavior['auth_attempts']) >= 2:
            time_diff = behavior['auth_attempts'][-1] - behavior['auth_attempts'][-2]
            if time_diff < self.config['auth_retry_minimum_seconds']:
                return f"Rapid auth retry: {time_diff:.1f}s between attempts (min: {self.config['auth_retry_minimum_seconds']}s)"

        return None

    # Call Duration Anomaly Detection

    def _extract_call_duration(self, log_line):
        """Extract call duration from CDR or channel hangup messages"""
        match = re.search(r'duration[=:\s]+(\d+)', log_line, re.IGNORECASE)
        if match:
            return int(match.group(1))

        match = re.search(r'billsec[=:\s]+(\d+)', log_line, re.IGNORECASE)
        if match:
            return int(match.group(1))

        return None

    def _check_call_duration_anomaly(self, ip, duration):
        """Detect suspicious call duration patterns. Returns violation reason or None"""
        if not self.config['call_duration_enabled']:
            return None

        if duration is None:
            return None

        behavior = self.behavior_data[ip]

        # Track call duration
        behavior['call_durations'].append(duration)

        # Keep only recent call data (last 50 calls)
        if len(behavior['call_durations']) > 50:
            behavior['call_durations'] = behavior['call_durations'][-50:]

        # Check for suspicious short calls
        short_calls = [d for d in behavior['call_durations'] if d <= self.config['suspicious_call_duration_max']]

        if len(short_calls) >= self.config['suspicious_call_count_threshold']:
            avg_duration = sum(behavior['call_durations']) / len(behavior['call_durations'])
            return f"Suspicious call pattern: {len(short_calls)} calls <={self.config['suspicious_call_duration_max']}s (avg: {avg_duration:.1f}s)"

        return None

    def _get_host_ip(self):
        """Get the host machine's IP address"""
        try:
            result = subprocess.run(
                ["hostname", "-I"],
                capture_output=True,
                text=True,
                check=True
            )
            ip = result.stdout.strip().split()[0]
            logging.info(f"Host IP detected: {ip}")
            return ip
        except Exception as e:
            logging.error(f"Could not detect host IP: {e}")
            return None

    def _load_state(self):
        """Load blocked and ignored IPs from files"""
        # Load blocked IPs
        if self.blocked_ips_file.exists():
            try:
                with open(self.blocked_ips_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        ip = line.split('#')[0].strip().split()[0] if line else ''
                        if ip and self._is_valid_ip(ip):
                            self.blocked_ips.add(ip)
                logging.info(f"Loaded {len(self.blocked_ips)} blocked IPs")
            except Exception as e:
                logging.error(f"Error loading blocked IPs: {e}")

        # Load ignore IPs
        if self.ignore_ips_file.exists():
            try:
                with open(self.ignore_ips_file, 'r') as f:
                    self.ignore_ips = set(line.strip() for line in f if line.strip() and not line.strip().startswith('#'))
                logging.info(f"Loaded {len(self.ignore_ips)} ignored IPs")
            except Exception as e:
                logging.error(f"Error loading ignore IPs: {e}")
        else:
            logging.warning(f"Ignore IPs file not found: {self.ignore_ips_file}")
            logging.warning("Create this file and add your legitimate IP addresses!")

        # Load watch IPs
        if self.watch_ips_file.exists():
            try:
                with open(self.watch_ips_file, 'r') as f:
                    self.watch_ips = json.load(f)
                logging.info(f"Loaded {len(self.watch_ips)} watched IPs")
            except Exception as e:
                logging.error(f"Error loading watch IPs: {e}")

    def _save_state(self):
        """Save blocked IPs to file with file locking and timestamps"""
        try:
            # Read existing timestamps to preserve them
            existing_timestamps = {}
            if self.blocked_ips_file.exists():
                try:
                    with open(self.blocked_ips_file, 'r') as f:
                        for line in f:
                            if '# Blocked' in line:
                                parts = line.strip().split(' # Blocked ')
                                if len(parts) == 2:
                                    ip = parts[0].strip()
                                    timestamp = parts[1].strip()
                                    existing_timestamps[ip] = timestamp
                except Exception:
                    pass

            with open(self.blocked_ips_file, 'w') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    now = datetime.datetime.now().isoformat()
                    for ip in sorted(self.blocked_ips):
                        timestamp = existing_timestamps.get(ip, now)
                        f.write(f"{ip} # Blocked {timestamp}\n")
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
            if self.debug:
                logging.debug(f"Saved {len(self.blocked_ips)} blocked IPs to state file")
        except Exception as e:
            logging.error(f"Error saving state: {e}")

    def _is_valid_ip(self, ip):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_whitelisted(self, ip):
        """Check if IP is in any whitelisted network - these should NEVER be blocked"""
        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check against configured whitelist networks
            for network_str in self.config.get("whitelist_networks", []):
                try:
                    network = ipaddress.ip_network(network_str, strict=False)
                    if ip_obj in network:
                        logging.debug(f"IP {ip} is whitelisted (in {network_str})")
                        return True
                except ValueError:
                    logging.warning(f"Invalid whitelist network: {network_str}")

            # Also check broadcast
            if str(ip) == "255.255.255.255":
                return True

            return False
        except ValueError:
            return False

    def _extract_ip(self, log_line):
        """Extract IP address from log line"""
        for pattern in self.config["ip_extraction_patterns"]:
            match = re.search(pattern, log_line)
            if match:
                ip = match.group(1)
                if self._is_valid_ip(ip):
                    return ip
        return None

    def _should_block(self, log_line):
        """Check if log line matches blocking patterns"""
        for pattern in self.config["block_patterns"]:
            if re.search(pattern, log_line, re.IGNORECASE):
                return True
        return False

    def block_ip(self, ip, reason):
        """Block an IP address using iptables"""
        with self.lock:
            # Validate IP format
            if not self._is_valid_ip(ip):
                logging.error(f"Invalid IP format: {ip}")
                return False

            # Check whitelist - NEVER block whitelisted IPs
            if self._is_whitelisted(ip):
                logging.info(f"IP {ip} is whitelisted, not blocking")
                return False

            # Check ignore list
            if ip in self.ignore_ips:
                logging.info(f"IP {ip} is in ignore list, not blocking")
                return False

            # Check if it's the host IP
            if ip == self.host_ip:
                logging.warning(f"Attempted to block host IP {ip}, skipping for safety")
                return False

            # Check if already blocked
            if ip in self.blocked_ips:
                if self.debug:
                    logging.debug(f"IP {ip} already blocked")
                return True

            # Handle IPv6 policy
            try:
                ip_obj = ipaddress.ip_address(ip)
                if isinstance(ip_obj, ipaddress.IPv6Address):
                    if self.config['block_all_ipv6']:
                        logging.info(f"IPv6 blocked by policy: {ip} - {reason}")
                        self.blocked_ips.add(ip)
                        self._save_state()
                        return True
            except ValueError:
                pass

            # Block with iptables
            try:
                check_cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
                result = subprocess.run(check_cmd, capture_output=True, text=True)

                if result.returncode != 0:
                    block_cmd = [
                        "iptables", "-I", "INPUT",
                        "-s", ip,
                        "-j", "DROP",
                        "-m", "comment", "--comment", f"KobraKai: {reason[:30]}"
                    ]
                    subprocess.run(block_cmd, check=True, capture_output=True)
                    logging.warning(f"BLOCKED: {ip} - {reason}")
                else:
                    if self.debug:
                        logging.debug(f"iptables rule already exists for {ip}")

                self.blocked_ips.add(ip)
                self._save_state()
                return True

            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to block {ip}: {e}")
                return False
            except Exception as e:
                logging.error(f"Error blocking {ip}: {e}")
                return False

    def add_to_watchlist(self, ip, reason):
        """Add IP to watchlist for monitoring"""
        now = time.time()

        if ip not in self.watch_ips:
            self.watch_ips[ip] = {
                "attempts": 0,
                "first_seen": now,
                "last_seen": now,
                "reasons": []
            }

        watch_entry = self.watch_ips[ip]
        watch_entry["attempts"] += 1
        watch_entry["last_seen"] = now
        if reason not in watch_entry["reasons"]:
            watch_entry["reasons"].append(reason)

        # Check if should block
        if watch_entry["attempts"] >= self.config["max_watch_attempts"]:
            if now - watch_entry["first_seen"] <= self.config["watch_window_seconds"]:
                logging.info(
                    f"Watch threshold exceeded for {ip}: {watch_entry['attempts']} attempts in {int(now - watch_entry['first_seen'])}s")
                self.block_ip(ip, f"Watch threshold: {'; '.join(watch_entry['reasons'][:2])}")
                del self.watch_ips[ip]
                return

        if self.debug:
            logging.debug(
                f"IP {ip} on watchlist: {watch_entry['attempts']}/{self.config['max_watch_attempts']} attempts")

    def cleanup_watchlist(self):
        """Remove old entries from watchlist"""
        now = time.time()
        to_remove = []

        for ip, data in self.watch_ips.items():
            if now - data["last_seen"] > self.config["watch_window_seconds"]:
                to_remove.append(ip)

        for ip in to_remove:
            del self.watch_ips[ip]

        if to_remove and self.debug:
            logging.debug(f"Cleaned up {len(to_remove)} expired watch entries")

    def process_log_line(self, line):
        """Process a single log line for threats"""
        # Extract IP first
        ip = self._extract_ip(line)
        if not ip:
            return

        # Skip if in ignore list
        if ip in self.ignore_ips:
            return

        # Skip if already blocked
        if ip in self.blocked_ips:
            return

        # Check IPv6 blocking policy
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv6Address) and self.config['block_all_ipv6']:
                self.block_ip(ip, "IPv6 policy violation")
                return
        except ValueError:
            pass

        # Check geo-blocking FIRST
        if self.config['geoip_enabled']:
            allowed, country = self._check_geolocation(ip)
            if not allowed:
                self.block_ip(ip, f"Geo-blocked: {country}")
                return

        # Check rate limiting
        rate_violation = self._check_rate_limit(ip)
        if rate_violation:
            self.block_ip(ip, f"Rate limit: {rate_violation}")
            return

        # Check User-Agent
        user_agent = self._extract_user_agent(line)
        if user_agent:
            ua_violation = self._check_user_agent(ip, user_agent)
            if ua_violation:
                self.block_ip(ip, ua_violation)
                return

        # Check honeypot extension protection + sequential scanning
        if self.config['honeypot_enabled']:
            extension = self._extract_extension(line)
            if extension:
                if not self._is_valid_extension(extension):
                    self.block_ip(ip, f"HONEYPOT: Invalid extension {extension}")
                    return

                # Check for sequential scanning patterns
                if self.config['sequential_scan_enabled']:
                    seq_violation = self._check_sequential_scan(ip, extension)
                    if seq_violation:
                        self.block_ip(ip, seq_violation)
                        return

        # Check SIP method abuse
        sip_method = self._extract_sip_method(line)
        if sip_method:
            method_violation = self._check_sip_method_abuse(ip, sip_method)
            if method_violation:
                self.block_ip(ip, method_violation)
                return

        # Check authentication timing
        auth_violation = self._check_auth_timing(ip, line)
        if auth_violation:
            self.block_ip(ip, auth_violation)
            return

        # Check call duration anomalies
        call_duration = self._extract_call_duration(line)
        if call_duration is not None:
            duration_violation = self._check_call_duration_anomaly(ip, call_duration)
            if duration_violation:
                self.block_ip(ip, duration_violation)
                return

        # Check existing blocking patterns
        if self._should_block(line):
            reason = "Pattern match"
            for pattern in self.config["block_patterns"]:
                if re.search(pattern, line, re.IGNORECASE):
                    reason = pattern[:50]
                    break

            # Update learned patterns
            if self.config['learning_mode']:
                pattern_sig = f"{reason}|{line[:100]}"
                self._update_learned_pattern(pattern_sig, ip)

            self.block_ip(ip, reason)

    def get_last_position(self):
        """Get last read position from file"""
        if self.position_file.exists():
            try:
                with open(self.position_file, 'r') as f:
                    return int(f.read().strip())
            except Exception as e:
                logging.error(f"Error reading position file: {e}")
        return 0

    def save_position(self, position):
        """Save current read position to file"""
        try:
            with open(self.position_file, 'w') as f:
                f.write(str(position))
        except Exception as e:
            logging.error(f"Error saving position: {e}")

    def process_log_file(self):
        """Process new lines from the log file"""
        log_file = self.config["log_file"]

        if not os.path.exists(log_file):
            if self.debug:
                logging.debug(f"Log file not found: {log_file}")
            return

        try:
            last_position = self.get_last_position()

            # Check for log rotation
            current_size = os.path.getsize(log_file)
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

    def cleanup_iptables_and_blocklist(self):
        """Clean up duplicate iptables rules and remove whitelisted IPs from blocklist"""
        logging.info("Starting iptables and blocklist cleanup...")

        # Get all current iptables rules
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
                capture_output=True, text=True, check=True
            )
            lines = result.stdout.split('\n')
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to list iptables rules: {e}")
            return 0, 0

        # Parse rules and find KobraKai entries
        kobrakai_rules = {}
        for line in lines:
            if 'KobraKai' in line or 'DROP' in line:
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                line_match = re.match(r'^(\d+)', line)
                if match and line_match:
                    ip = match.group(1)
                    line_num = int(line_match.group(1))
                    if ip not in kobrakai_rules:
                        kobrakai_rules[ip] = []
                    kobrakai_rules[ip].append(line_num)

        # Find rules to delete
        rules_to_delete = []

        for ip, line_numbers in kobrakai_rules.items():
            if self._is_whitelisted(ip):
                for ln in line_numbers:
                    rules_to_delete.append((ln, ip, "whitelisted"))
                logging.info(f"Will remove {len(line_numbers)} rules for whitelisted IP: {ip}")
            elif len(line_numbers) > 1:
                sorted_lines = sorted(line_numbers)
                for ln in sorted_lines[1:]:
                    rules_to_delete.append((ln, ip, "duplicate"))
                logging.info(f"Will remove {len(line_numbers) - 1} duplicate rules for IP: {ip}")

        # Delete rules in reverse order
        rules_to_delete.sort(key=lambda x: x[0], reverse=True)
        deleted_count = 0
        for line_num, ip, reason in rules_to_delete:
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", str(line_num)],
                    check=True, capture_output=True
                )
                deleted_count += 1
                logging.debug(f"Deleted rule {line_num} for {ip} ({reason})")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to delete rule {line_num}: {e}")

        logging.info(f"Deleted {deleted_count} iptables rules")

        # Clean up blocked_ips.txt
        unique_ips = set()
        removed_whitelisted = []

        for ip in list(self.blocked_ips):
            clean_ip = ip.split('#')[0].split()[0].strip() if ip else ''
            if not clean_ip or not self._is_valid_ip(clean_ip):
                continue

            if self._is_whitelisted(clean_ip):
                removed_whitelisted.append(clean_ip)
            else:
                unique_ips.add(clean_ip)

        if removed_whitelisted:
            logging.info(f"Removed {len(removed_whitelisted)} whitelisted IPs from blocklist")

        old_count = len(self.blocked_ips)
        self.blocked_ips = unique_ips
        self._save_state()
        logging.info(f"Blocklist cleaned: {old_count} -> {len(self.blocked_ips)} entries")

        logging.info("Cleanup complete!")
        return deleted_count, len(removed_whitelisted)

    def cleanup_expired_blocks(self):
        """Remove blocks older than configured time (optional maintenance)"""
        logging.info(f"Current state: {len(self.blocked_ips)} blocked IPs, {len(self.watch_ips)} watched IPs")

        # Cleanup learned patterns
        if self.config['learning_mode']:
            cutoff = datetime.datetime.now() - datetime.timedelta(days=self.config['pattern_cleanup_days'])
            to_remove = []

            for pattern_sig, pattern_data in self.learned_patterns.items():
                last_seen = datetime.datetime.fromisoformat(pattern_data['last_seen'])
                if last_seen < cutoff and not pattern_data['auto_blocked']:
                    to_remove.append(pattern_sig)

            for pattern_sig in to_remove:
                del self.learned_patterns[pattern_sig]

            if to_remove:
                logging.info(f"Cleaned up {len(to_remove)} stale learned patterns")
                self._save_learned_patterns()

    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logging.info(f"Received signal {signum}, shutting down...")
        self.running = False

    def get_ip_behavior_summary(self, ip):
        """Get behavioral analysis summary for an IP"""
        if ip not in self.behavior_data:
            return None

        behavior = self.behavior_data[ip]

        extension_count = len(behavior['extension_attempts'])
        unique_extensions = len(set(att['extension'] for att in behavior['extension_attempts']))

        sip_method_summary = {}
        for method, timestamps in behavior['sip_methods'].items():
            sip_method_summary[method] = len(timestamps)

        auth_attempt_count = len(behavior['auth_attempts'])

        call_count = len(behavior['call_durations'])
        avg_call_duration = sum(behavior['call_durations']) / call_count if call_count > 0 else 0
        short_calls = sum(1 for d in behavior['call_durations'] if d <= self.config['suspicious_call_duration_max'])

        return {
            'user_agents': behavior['user_agents'],
            'extension_attempts': extension_count,
            'unique_extensions': unique_extensions,
            'sip_methods': sip_method_summary,
            'auth_attempts': auth_attempt_count,
            'total_calls': call_count,
            'avg_call_duration': avg_call_duration,
            'short_calls': short_calls
        }

    def run(self):
        """Main monitoring loop"""
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

        logging.info("KobraKai starting...")
        logging.info(f"Monitoring: {self.config['log_file']}")
        logging.info(f"Data directory: {self.data_dir}")

        self.running = True
        last_cleanup = time.time()
        last_extension_refresh = time.time()

        try:
            while self.running:
                self.process_log_file()

                # Periodic cleanup (every 5 minutes)
                if time.time() - last_cleanup > 300:
                    self.cleanup_watchlist()
                    self.cleanup_expired_blocks()
                    last_cleanup = time.time()

                # Periodic extension refresh
                if (self.config['honeypot_enabled'] and
                        self.config['auto_detect_extensions'] and
                        time.time() - last_extension_refresh > self.config['extension_refresh_interval']):
                    detected = self._auto_detect_extensions()
                    if detected:
                        self.valid_extensions.update(detected)
                        logging.info(f"Extension refresh: {len(self.valid_extensions)} total valid extensions")
                    last_extension_refresh = time.time()

                time.sleep(self.config["poll_interval"])

        except KeyboardInterrupt:
            logging.info("Interrupted by user")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            raise
        finally:
            self._save_state()
            if self.config['learning_mode']:
                self._save_learned_patterns()
            if self.geoip_reader:
                self.geoip_reader.close()
            logging.info("KobraKai stopped")


def main():
    parser = argparse.ArgumentParser(description="KobraKai - VoIP Security Monitor")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--test-ip", help="Test blocking functionality with IP")
    parser.add_argument("--list-blocked", action="store_true", help="List currently blocked IPs")
    parser.add_argument("--unblock", help="Remove IP from block list")
    parser.add_argument("--show-extensions", action="store_true", help="Show detected/configured extensions")
    parser.add_argument("--refresh-extensions", action="store_true", help="Force extension re-scan")
    parser.add_argument("--test-extension", help="Test if extension would be blocked")
    parser.add_argument("--show-learned-patterns", action="store_true", help="Show learned attack patterns")
    parser.add_argument("--show-behavior", help="Show behavioral analysis for IP address")
    parser.add_argument("--cleanup", action="store_true", help="Clean up duplicate iptables rules and remove whitelisted IPs")

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

    if args.show_extensions:
        print(
            f"\nValid Extensions ({len(monitor.valid_extensions)} exact + {len(monitor.extension_patterns)} patterns + {len(monitor.extension_ranges)} ranges):")
        print(f"\nExact matches: {sorted(monitor.valid_extensions) if monitor.valid_extensions else 'None'}")
        print(f"Patterns: {[p.pattern for p in monitor.extension_patterns] if monitor.extension_patterns else 'None'}")
        print(f"Ranges: {monitor.extension_ranges if monitor.extension_ranges else 'None'}")
        return

    if args.refresh_extensions:
        print("Refreshing extensions...")
        detected = monitor._auto_detect_extensions()
        if detected:
            monitor.valid_extensions.update(detected)
            print(f"Detected {len(detected)} extensions")
            print(f"Total valid extensions: {len(monitor.valid_extensions)}")
        else:
            print("No extensions detected")
        return

    if args.test_extension:
        is_valid = monitor._is_valid_extension(args.test_extension)
        if is_valid:
            print(f"Extension {args.test_extension} is VALID (would be allowed)")
        else:
            print(f"Extension {args.test_extension} would be BLOCKED (honeypot trigger)")
        return

    if args.show_learned_patterns:
        print(f"\nLearned Attack Patterns ({len(monitor.learned_patterns)}):")
        for sig, data in sorted(monitor.learned_patterns.items(), key=lambda x: x[1]['severity'], reverse=True):
            print(f"  {sig}")
            print(f"    Severity: {data['severity']}/100  Count: {data['count']}  Auto-blocked: {data['auto_blocked']}")
            print(f"    First: {data['first_seen'][:19]}  Last: {data['last_seen'][:19]}")
        return

    if args.cleanup:
        print("Running cleanup...")
        print(f"Whitelist networks: {monitor.config.get('whitelist_networks', [])}")
        deleted_rules, removed_ips = monitor.cleanup_iptables_and_blocklist()
        print(f"\nCleanup complete:")
        print(f"  - Deleted {deleted_rules} iptables rules (duplicates + whitelisted)")
        print(f"  - Removed {removed_ips} whitelisted IPs from blocklist")
        print(f"  - Blocklist now has {len(monitor.blocked_ips)} unique IPs")
        return

    if args.show_behavior:
        behavior = monitor.get_ip_behavior_summary(args.show_behavior)
        if behavior:
            print(f"\n=== Behavioral Analysis for {args.show_behavior} ===")
            print(f"\nUser-Agents ({len(behavior['user_agents'])}):")
            for ua in behavior['user_agents'][:10]:
                print(f"  - {ua}")
            if len(behavior['user_agents']) > 10:
                print(f"  ... and {len(behavior['user_agents']) - 10} more")

            print(f"\nExtension Attempts:")
            print(f"  Total attempts: {behavior['extension_attempts']}")
            print(f"  Unique extensions: {behavior['unique_extensions']}")

            print(f"\nSIP Methods:")
            for method, count in sorted(behavior['sip_methods'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {method}: {count} requests")

            print(f"\nAuthentication:")
            print(f"  Failed attempts: {behavior['auth_attempts']}")

            print(f"\nCall Statistics:")
            print(f"  Total calls: {behavior['total_calls']}")
            print(f"  Average duration: {behavior['avg_call_duration']:.1f}s")
            print(f"  Short calls (<={monitor.config['suspicious_call_duration_max']}s): {behavior['short_calls']}")
        else:
            print(f"No behavioral data found for {args.show_behavior}")
        return

    # Run main monitoring loop
    monitor.run()


if __name__ == "__main__":
    main()
