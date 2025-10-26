# KobraKai v2.0 - No Mercy VoIP Hacker Blocker

## Overview

KobraKai is a powerful security tool designed to protect FreePBX/Asterisk systems from brute force attacks and unauthorized access attempts. Version 2.0 introduces significant improvements to handle the specific attack patterns you're experiencing.

## Key Features

* **Proactive Defense:** Blocks attackers on first suspicious activity
* **Enhanced Attack Detection:** Identifies malformed SIP packets and reconnaissance attempts
* **Resource Efficient:** Minimizes memory, CPU, and disk usage
* **Rate Limiting:** Blocks IPs exceeding configurable connection thresholds
* **Subnet Blocking:** Option to block entire subnets when multiple IPs from same range attack
* **Pattern Recognition:** Identifies and blocks common attack signatures
* **Comprehensive Logging:** With automatic log rotation to conserve disk space
* **Export Functionality:** Export blocked IPs for firewall integration

### Latest update

The update now covers all the following attack vectors:

* **All SIP Methods:** REGISTER, INVITE, OPTIONS, SUBSCRIBE, NOTIFY, MESSAGE, REFER, UPDATE, PRACK, INFO, PUBLISH
* **Extension Enumeration:** Detects IPs trying multiple extensions
* **Protocol Violations:** Invalid headers, missing requirements, malformed SDP
* **Authentication Attacks:** Digest failures, multiple attempts, replay attacks
* **Media Attacks:** RTP/SRTP failures
* **Flooding/DoS:** Maximum retries, too many attempts
* **Scanning:** OPTIONS probes, version fingerprinting
* **Spam:** MESSAGE method abuse

## Installation

```bash
# Clone the repository
git clone https://github.com/fxpro32/kobrakai.git
cd kobrakai

# Run the installer script as root
sudo bash install-kobrakai.sh
```

### Important: Prevent Self-Lockout

Before running KobraKai, add your own IP addresses to the ignore list:

```bash
echo "YOUR_IP" >> /home/KobraKai/ignore-list.txt
```

## Configuration

Edit the config file at `/home/KobraKai/kobrakai-config.json`:

```json
{
  "log_file": "/var/log/asterisk/full",
  "ignore_list_file": "/home/KobraKai/ignore-list.txt",
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

* **rate_limit_attempts:** Maximum connection attempts allowed in the time window (default: 3)
* **rate_limit_window:** Time window in seconds for rate limiting (default: 60)
* **block_subnet_threshold:** Number of IPs from same subnet to trigger subnet blocking (default: 5)
* **enable_subnet_blocking:** Enable/disable blocking entire subnets (default: false)
* **attack_patterns:** Regular expressions to match against log lines

## Managing the Service

KobraKai runs as a system service:

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

## Enhanced Protections in v2.0

KobraKai v2.0 addresses the specific issues you were facing:

* **Immediate Blocking of Reconnaissance Attempts:** Detects and blocks malformed SIP packets and syntax errors immediately.
* **First-Attempt Blocking:** Suspicious IPs are blocked after the first failed registration attempt based on pattern recognition.
* **Rate Limiting:** Automatically blocks IPs that exceed the configured connection rate threshold.
* **Pattern Recognition:** Categorizes attacks by severity for appropriate response.
* **Resource Optimization:** Minimizes resource usage while maintaining robust protection.

## How It Works

When KobraKai detects suspicious activity:

* High severity patterns (like malformed packets) trigger immediate blocking
* Medium severity patterns either trigger blocking or add the IP to a watch list
* Low severity patterns add the IP to a watch list
* IPs on the watch list are blocked if they continue suspicious activity
* Rate limiting blocks IPs making too many connection attempts
* All blocked IPs are saved to the hacker IPs list and iptables

## Troubleshooting

If you encounter issues:

```bash
# Check the logs
tail -f /home/KobraKai/kobrakai.log

# Check the service status
systemctl status kobrakai.service
```

### Additional checks

* Ensure Python 3 and required packages (watchdog) are installed.
* Confirm Asterisk logs are readable by the KobraKai user.

## License

**KobraKai - VoIP Hacker Blocker Script**
Copyright (c) 2025 FXPRO

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. USE AT YOUR OWN RISK.

## Author

Created and maintained by [fxpro32](https://github.com/fxpro32)

If you encounter any issues or have questions, please open an issue on the [GitHub repository](https://github.com/fxpro32/kobrakai/issues).
