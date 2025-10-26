# KobraKai v2.3 - Advanced VoIP Security Protection System (Enhanced Edition)

## Overview

KobraKai v2.3 is a **production-ready VoIP intrusion prevention system** designed to protect **FreePBX**, **Asterisk**, and **Sangoma** systems against unauthorized access attempts, brute-force attacks, and reconnaissance scans. It continuously monitors Asterisk logs in real time and takes immediate defensive action against malicious IPs using a **thread-safe**, **atomic**, and **idempotent** architecture.

---

## Key Features

* ⚡ **Real-time monitoring** of Asterisk log files for attack signatures
* 🛡 **Immediate blocking** of reconnaissance attempts and malformed SIP packets
* 🔒 **Thread-safe operations** with file and state locking
* 🧩 **Single atomic blocking path** to eliminate infinite loops and race conditions
* 🧠 **Pattern recognition** for common VoIP attack vectors
* 🧱 **Comprehensive IP blocking** via persistent iptables rules
* 🪶 **Resource-efficient** operation with minimal system impact
* 🧾 **Configurable JSON-based security policies**
* 🧰 **Built-in management tools** for listing, unblocking, and testing IPs
* 🪵 **Structured logging** with robust error handling and graceful shutdown

---

## Enhanced Security Features (v2.3+)

* 🛡 Robust architecture prevents infinite blocking loops
* 🔒 Thread-safe operations with proper state locking
* ⚡ Single atomic blocking path for all security decisions
* 📊 Clean iptables rule management with verification
* 🎯 Reliable log position tracking with rotation handling
* 💾 Enhanced pattern recognition for malformed packet detection
* 🧰 Built-in diagnostic and management commands
* 📝 Comprehensive logging and graceful shutdown handling
* 🚀 Production-ready with persistent state management

---

## Attack Mitigation Capabilities

KobraKai v2.3 defends against the following:

* **SIP endpoint enumeration** – immediate blocking on first attempt
* **Malformed PJSIP syntax attacks** – critical threat response
* **Authentication brute-force attacks** – progressive detection and blocking
* **OPTIONS flood and DoS attacks** – rate-based detection and mitigation
* **Extension enumeration scans** – tracked via a dynamic watch list
* **Protocol violations** – pattern-based analysis and response
* **Reconnaissance scanning** – first-attempt blocking for unknown endpoints

---

## Important Security Warning ⚠️

KobraKai **will block unauthorized SIP/IAX registration attempts**. To prevent self-lockout, **add your trusted IP addresses** to the ignore list *before running* the software:

```bash
echo "YOUR_IP" >> /home/KobraKai/ignore_ips.txt
```

Each IP should be on a separate line.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/fxpro32/kobrakai.git
cd kobrakai

# Run the installer script as root
sudo bash install-kobrakai.sh
```

---

## Usage

```bash
Standard mode:     python3 kobrakai-v2.py
Debug mode:        python3 kobrakai-v2.py --debug
Test blocking:     python3 kobrakai-v2.py --test-ip 1.2.3.4
List blocked IPs:  python3 kobrakai-v2.py --list-blocked
Remove IP:         python3 kobrakai-v2.py --unblock 1.2.3.4
Custom config:     python3 kobrakai-v2.py --config /path/to/config.json
```

---

## Configuration

Default configuration file:
`/home/KobraKai/kobrakai-config.json`

```json
{
  "log_file": "/var/log/asterisk/full",
  "ignore_list_file": "/home/KobraKai/ignore_ips.txt",
  "hacker_ips_file": "/home/KobraKai/hacker-ips-list.txt",
  "watch_list_file": "/home/KobraKai/watch-list.json",
  "log_rotation_days": 7,
  "log_max_size_mb": 10,
  "rate_limit_attempts": 3,
  "rate_limit_window": 60,
  "block_subnet_threshold": 5,
  "enable_pattern_recognition": true,
  "enable_rate_limiting": true,
  "enable_subnet_blocking": false,
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
```

### Key Configuration Options

* **rate_limit_attempts:** Max failed connection attempts before blocking
* **rate_limit_window:** Time window in seconds for rate limiting
* **block_subnet_threshold:** Number of IPs from same subnet to trigger subnet blocking
* **enable_subnet_blocking:** Enables subnet-wide blocking for coordinated attacks
* **attack_patterns:** Regex-based detection signatures

---

## Managing the Service

KobraKai runs as a systemd service:

```bash
# Check service status
systemctl status kobrakai.service

# Start the service
systemctl start kobrakai.service

# Stop the service
systemctl stop kobrakai.service

# Restart the service
systemctl restart kobrakai.service

# View logs
tail -f /home/KobraKai/kobrakai.log
```

---

## Performance and Reliability

* Efficient log polling with file position tracking
* Thread-safe file access using locks
* Atomic writes to prevent corruption
* Memory-efficient pattern matching
* Clean and verified iptables rule handling
* Persistent runtime state maintained across restarts

---

## Recovery Procedure

If you accidentally get locked out:

```bash
# 1. Log in locally to the server
# 2. Remove your IP from block list
python3 /home/KobraKai/kobrakai-v2.py --unblock YOUR_IP

# 3. Add your IP to the ignore list
echo "YOUR_IP" >> /home/KobraKai/ignore_ips.txt

# 4. Remove iptables rule manually if necessary
iptables -D INPUT -s YOUR_IP -m comment --comment 'KobraKai_Block' -j DROP

# 5. Restart the service
systemctl restart kobrakai.service
```

---

## System Requirements

* Python 3.6 or newer
* iptables with comment module (`-m comment`)
* Root/sudo privileges for firewall changes
* Read access to Asterisk logs
* Write access to `/home/KobraKai/` for state/config files

---

## System Architecture

* Single atomic blocking path prevents recursive operations
* Thread-safe with file and process-level locking
* Atomic temporary file writes for integrity
* Idempotent iptables operations safe to repeat
* Persistent runtime state maintained across restarts
* Graceful signal handling for clean shutdown

---

## Changelog (v2.3 Enhanced Edition)

* ✨ Full architectural rewrite for stability and reliability
* 🧱 Removed infinite loop and race condition risks
* ⚙️ Implemented single atomic blocking path
* 🔒 Added state management with locking
* 🔍 Improved iptables rule verification and cleanup
* 🧰 Added diagnostic and management commands
* 🧾 Enhanced log tracking and rotation handling
* 🚦 Implemented graceful shutdown signal handling
* 🐞 Fixed all known issues from v2.0-v2.2

---

## License

**KobraKai - VoIP Security Protection System**
Copyright (c) 2025 **FXPRO (Pietro Casoar)**

This software is provided under an MIT-style license:

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. USE AT YOUR OWN RISK.

## Author

Created and maintained by [fxpro32](https://github.com/fxpro32)

If you encounter any issues or have questions, please open an issue on the [GitHub repository](https://github.com/fxpro32/kobrakai/issues).
