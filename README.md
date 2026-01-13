# KobraKai

**No Mercy VoIP Hacker Blocker for FreePBX/Asterisk**

```
██╗  ██╗ ██████╗ ██████╗ ██████╗  █████╗ ██╗  ██╗ █████╗ ██╗
██║ ██╔╝██╔═══██╗██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██║
█████╔╝ ██║   ██║██████╔╝██████╔╝███████║█████╔╝ ███████║██║
██╔═██╗ ██║   ██║██╔══██╗██╔══██╗██╔══██║██╔═██╗ ██╔══██║██║
██║  ██╗╚██████╔╝██████╔╝██║  ██║██║  ██║██║  ██╗██║  ██║██║
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
```

KobraKai is a real-time VoIP intrusion prevention system designed to protect FreePBX and Asterisk systems from hackers, toll fraud, and brute-force attacks. It monitors your Asterisk logs and immediately blocks malicious IP addresses using iptables.

---

## Why KobraKai Exists

### The Story Behind the Code

This software was born from a painful and expensive lesson in trust, corporate negligence, and the complete failure of existing security tools.

For many years, I worked in the VoIP industry, providing services to customers and friends. I'd experienced hacking attempts and toll fraud before, but nothing prepared me for what happened in 2015.

I had installed a VoIP IPPBX for a friend. Almost immediately, hackers launched a brutal attack on the system, resulting in just under $100 AUD in toll fraud. Annoying, but manageable. I called my SIP trunk provider at the time, **Internode** (an Australian ISP), and asked their support representative to block all international and satellite calls as a precaution.

The rep's response? *"Nah, you don't need to do that. I'll fix it from my end."*

Being naive and trusting at the time, I accepted this. I assumed this decision was noted in Internode's system. It wasn't.

**Three days later, hackers struck again.** This time, the toll fraud exceeded **$5, 000 AUD**, money I ultimately had to pay out of my own pocket.

When I disputed the charges, Internode reneged on their word. Their position was simple: if I couldn't produce a call record proving I'd contacted their support, then the call "didn't exist." We all know that's bollocks, any reputable ISP records and logs all calls. I later learned from an insider that **my call WAS logged**, but to protect the support representative, I was made the scapegoat, and the supervisor managing the situation knew full well what he was doing.

Why couldn't I find my own call record at the time? Because I'd made the call from a different phone, and this all happened approximately a week after my father passed away. I wasn't in the right frame of mind. I couldn't locate the record, and that was all Internode needed to deny responsibility. This was a very expensive lesson NEVER to communicate over a voice phone call when such issues arise, but to ALWAYS use email so that a paper trail can be made and referred back to, when/if the need arises.

The Telecommunications Industry Ombudsman, who proved to be as useful as tits on a bull, sided with Internode. I was held fully responsible for fraud that could have been prevented with one checkbox.

To make matters worse, I had **Fail2Ban** installed and configured correctly on the system. **It failed miserably.** In my experience, Fail2Ban is fundamentally inadequate for protecting VoIP systems from determined attackers.

### From Victim to Victor

That experience lit a fire. I spent years researching VoIP attack vectors, running honeypot systems that absorbed SIP hack attempts without any connected trunk, studying the tactics hackers use, cataloguing their patterns, and developing countermeasures.

KobraKai is the culmination of that work: an intelligent, self-learning script that absorbs the first signs of an attack, learns the patterns, and mercilessly blocks every variation that follows. Where Fail2Ban failed, KobraKai does not.

Is anything truly unhackable? No. But KobraKai has successfully blocked **every SIP VoIP hacking attack** thrown at it in testing. It shows no mercy because the hackers certainly won't show any to you.

**The best defense is a good offense. Strike first. Strike hard. No mercy.**

---

## Features

### Core Protection
- **Real-time Log Monitoring** - Continuously monitors Asterisk logs for attack signatures
- **Instant IP Blocking** - Blocks attackers via iptables on first detection
- **Pattern Recognition** - Detects common VoIP attack vectors automatically
- **Self-Learning** - Learns and adapts to new attack patterns over time

### Advanced Detection
- **Geo-Blocking** - Block entire countries (requires free MaxMind database)
- **IPv6 SIP Blocking** - Blocks IPv6 on SIP ports while preserving web access
- **Honeypot Extensions** - Traps attackers probing for non-existent extensions
- **User-Agent Detection** - Identifies known scanner tools (SIPVicious, etc.)
- **Sequential Scan Detection** - Catches extension enumeration attacks
- **Rate Limiting** - Blocks burst attacks and slow-scan attempts
- **Auth Storm Detection** - Catches rapid authentication failures
- **SIP Method Abuse** - Detects OPTIONS floods and protocol anomalies
- **Call Duration Analysis** - Identifies fraud patterns

### Attack Types Blocked
- SIP endpoint enumeration
- PJSIP syntax error attacks
- Authentication brute force
- OPTIONS flood attacks
- Extension scanning
- Protocol violations
- Reconnaissance scanning
- Toll fraud attempts

### Why Not Fail2Ban? A Technical Autopsy

Fail2Ban was designed as a general-purpose intrusion prevention system. It works by parsing log files and banning IPs after a configurable number of failures. For SSH brute-force protection, it's adequate. For VoIP? It's dangerously insufficient.

This isn't opinion, it's documented fact. Here's the technical breakdown:

#### 1. Reactive, Not Proactive

Fail2Ban is fundamentally **reactive**. It waits for attacks to be logged, parses those logs, and *then* acts. For VoIP toll fraud, this is catastrophic:

- A single successful fraudulent call to a premium-rate number can cost $50+ in seconds
- By the time Fail2Ban's default `maxretry` of 3-5 failures triggers a ban, the attacker may have already succeeded
- Default ban time is only **10 minutes** (600 seconds), attackers simply wait and resume

As one security expert bluntly put it: *"Fail2ban does not provide any extra security; anybody relying on it for this purpose is in for a nasty surprise."*

#### 2. Distributed/Botnet Attacks Defeat It Entirely

Fail2Ban identifies attackers by IP address. Modern botnets use **distributed, low-and-slow attacks**:

- Hundreds or thousands of IPs each make only 1-2 attempts
- Individual IPs never trigger the `maxretry` threshold
- Attacks spread over hours or days evade `findtime` windows
- Even with aggressive settings (1-week `findtime`), false positives block legitimate users

From a GitHub issue on this exact problem: *"Most 'reasonable' findtimes (minutes or 1-3 hours) will not catch these IPs because they fail slowly. Longer findtimes run a significant risk of false positives."*

Fail2Ban's own Wikipedia page admits: *"Fail2Ban fails to protect against a distributed brute-force attack."*

#### 3. IP Spoofing Vulnerability

Attackers can weaponize Fail2Ban against you:

- Spoofed source headers can cause Fail2Ban to **block legitimate users**
- An attacker who knows your IP can get **you** locked out of your own server
- This creates a Denial of Service vector that attackers actively exploit

The Arch Linux Wiki explicitly warns: *"If the attacker knows your IP address, they can send packets with a spoofed source header and get your IP address locked out of the server."*

#### 4. Regex Maintenance Nightmare

Fail2Ban relies on regex patterns to match log entries. For Asterisk/FreePBX:

- **Log formats change between Asterisk versions** (1.4, 1.6, 1.8, 10+, 11, 13, 16, 18...)
- **chan_sip and PJSIP have different log formats**
- **PJSIP TLS logs differently again**, and often isn't caught at all
- The default Asterisk filter hasn't kept pace with Asterisk development

Real-world reports from administrators:
- *"I have tried 10 different filters but none of them show any matches"* (Asterisk 16 PJSIP)
- *"Fail2ban seems to work fine for SSH but anything related to SIP doesn't get caught"* (FreePBX 14)
- *"Fail2Ban not detecting PJSIP TLS Brute Force attempts"* (common complaint)
- *"The fail2ban configuration for Asterisk hasn't been updated in a while and I found a number of registration and outbound call attempts were not being detected"*

#### 5. Security Vulnerabilities in Fail2Ban Itself

Fail2Ban has its own history of CVEs:

| CVE | Impact |
|-----|--------|
| **CVE-2021-32749** | Remote Code Execution via mail-whois action |
| **CVE-2009-0362** | DoS via crafted reverse DNS entries (regex exploit) |
| **CVE-2007-4321** | Attackers can add arbitrary IPs to blocklist |
| **CVE-2006-6302** | Log injection causes blocking of arbitrary hosts |

The RCE vulnerability (CVE-2021-32749) allowed attackers to execute arbitrary code as root by manipulating whois responses. A tool meant to protect you became an attack vector.

#### 6. Log Spoofing Attacks

On shared hosting or multi-user systems, unprivileged users can write directly to syslog:

- Attackers can **inject fake log entries**
- This causes Fail2Ban to ban innocent IPs
- DNS resolvers, administrators, or legitimate users can be blocked
- One security researcher noted: *"A malicious user could block the DNS resolvers to disrupt the server or even block the administrators if their IP addresses are known."*

#### 7. No Understanding of VoIP Attack Patterns

Fail2Ban doesn't understand SIP. It can't detect:

- **Extension enumeration** (sequential scanning of 100, 101, 102...)
- **OPTIONS floods** (reconnaissance that doesn't trigger auth failures)
- **User-Agent fingerprinting** (SIPVicious, friendly-scanner, sipcli)
- **Protocol anomalies** (malformed SIP packets)
- **Behavioral patterns** (timing, cadence, call duration)
- **Toll fraud patterns** (calls to premium numbers)

It only sees what appears in logs matching its regex, everything else sails through.

#### 8. Performance Issues Under Attack

During heavy attacks, Fail2Ban can become part of the problem:

- Large iptables chains slow down rule processing
- High log volume causes CPU spikes
- The daemon itself can become unresponsive
- One administrator reported: *"fail2ban was managing/adding so many entries to iptables that it caused extremely slow system responses"*

#### 9. Temporary Bans = No Real Protection

The default configuration unbans attackers after 10 minutes:

- Attackers automate their tools to wait and retry
- Botnets simply rotate through IPs
- As one discussion noted: *"Having fail2ban on your house means you have a guy by the door who takes away the burglars keyring after he tries three incorrect keys, but then gives it back 10 minutes later."*

#### 10. Configuration Doesn't Survive Upgrades

Many administrators have discovered their carefully-crafted rules overwritten:

- FreePBX GUI can overwrite custom settings
- Package updates reset jail.conf
- Custom filters need constant maintenance
- Files like `logger_logfiles_custom.conf` must be used instead of main configs

---

**Bottom line:** Fail2Ban creates a dangerous illusion of security. It's better than nothing for SSH, but for protecting VoIP infrastructure from toll fraud? It's inadequate by design.

KobraKai was built specifically for VoIP protection with instant blocking, pattern learning, behavioral analysis, and aggressive detection that Fail2Ban simply cannot match.

---

## Requirements

- Python 3.6+
- FreePBX or Asterisk PBX
- Root/sudo access
- iptables with comment module
- (Optional) geoip2 Python library for geo-blocking

## Quick Start

### 1. Installation

```bash
# Create installation directory
sudo mkdir -p /opt/kobrakai/geoip

# Copy files
sudo cp kobrakai.py /opt/kobrakai/
sudo cp kobrakai-config.example.json /opt/kobrakai/kobrakai-config.json
sudo cp ignore_ips.example.txt /opt/kobrakai/ignore_ips.txt
sudo cp extensions.example.json /opt/kobrakai/extensions.json
sudo cp -r geoip/* /opt/kobrakai/geoip/

# Set permissions
sudo chmod +x /opt/kobrakai/kobrakai.py
sudo chmod +x /opt/kobrakai/geoip/download-geoip.sh
```

### 2. Configure Your Whitelist (CRITICAL!)

**Before starting KobraKai, you MUST add your IP addresses to prevent lockout:**

```bash
sudo nano /opt/kobrakai/ignore_ips.txt
```

Add:
- Your server's IP address
- Your office/home IP addresses
- Your VoIP trunk provider's IPs
- Any other IPs that should never be blocked

### 3. Configure Extensions (Recommended)

Edit `/opt/kobrakai/extensions.json` to define your valid extensions, or enable auto-detection in the config file.

### 4. Test Run

```bash
# Run in debug mode first
sudo python3 /opt/kobrakai/kobrakai.py --debug

# Test that your IP won't be blocked
sudo python3 /opt/kobrakai/kobrakai.py --test-ip YOUR_IP_ADDRESS
```

### 5. Install as Service

```bash
# Copy service file
sudo cp kobrakai.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable kobrakai
sudo systemctl start kobrakai

# Check status
sudo systemctl status kobrakai
```

## Configuration

### Main Config File (`kobrakai-config.json`)

```json
{
  "data_dir": "/opt/kobrakai",
  "log_file": "/var/log/asterisk/full",

  "honeypot_enabled": true,
  "auto_detect_extensions": true,

  "geoip_enabled": false,
  "allowed_countries": ["AU"],

  "whitelist_networks": [
    "127.0.0.0/8",
    "192.168.1.0/24"
  ],

  "burst_threshold": 5,
  "burst_window_seconds": 3,
  "auth_storm_threshold": 3
}
```

### Key Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `log_file` | Asterisk log file to monitor | `/var/log/asterisk/full` |
| `honeypot_enabled` | Enable honeypot extension trap | `true` |
| `auto_detect_extensions` | Auto-discover extensions from Asterisk | `true` |
| `geoip_enabled` | Enable country-based blocking | `false` |
| `allowed_countries` | List of allowed country codes | `["AU"]` |

> **Note:** The default `allowed_countries` value of `["AU"]` reflects the author's location in Australia. You should change this to your own country code(s) based on where your legitimate SIP traffic originates. For example, a US-based system might use `["US"]`, while a business with international offices might use `["US", "GB", "DE"]`.
| `block_all_ipv6` | Block IPv6 on SIP ports | `true` |
| `burst_threshold` | Requests before burst block | `5` |
| `auth_storm_threshold` | Auth failures before block | `3` |

## Geo-Blocking Setup

To enable geo-blocking, you need the free MaxMind GeoLite2 database:

1. **Register** at https://www.maxmind.com/en/geolite2/signup (free)
2. **Generate a license key** in your MaxMind account
3. **Download the database:**
   ```bash
   cd /opt/kobrakai/geoip
   ./download-geoip.sh YOUR_LICENSE_KEY
   ```
4. **Enable in config:**
   ```json
   {
     "geoip_enabled": true,
     "allowed_countries": ["AU", "NZ"]
   }
   ```

Common country codes: `US`, `GB`, `CA`, `AU`, `NZ`, `DE`, `FR`, `JP`

## Command Line Usage

```bash
# Start monitoring (normal mode)
python3 kobrakai.py

# Start with debug output
python3 kobrakai.py --debug

# Use custom config file
python3 kobrakai.py --config /path/to/config.json

# List all blocked IPs
python3 kobrakai.py --list-blocked

# Unblock an IP
python3 kobrakai.py --unblock 1.2.3.4

# Test if an IP would be blocked
python3 kobrakai.py --test-ip 1.2.3.4

# Show configured extensions
python3 kobrakai.py --show-extensions

# Test if extension would trigger honeypot
python3 kobrakai.py --test-extension 9999

# Force refresh extensions from Asterisk
python3 kobrakai.py --refresh-extensions

# Show learned attack patterns
python3 kobrakai.py --show-learned-patterns

# Show behavioral analysis for an IP
python3 kobrakai.py --show-behavior 1.2.3.4

# Clean up duplicate iptables rules
python3 kobrakai.py --cleanup
```

## Files

| File | Purpose |
|------|---------|
| `kobrakai.py` | Main script |
| `kobrakai-config.json` | Configuration file |
| `ignore_ips.txt` | IPs to never block (whitelist) |
| `extensions.json` | Valid extensions configuration |
| `blocked_ips.txt` | Auto-generated list of blocked IPs |
| `kobrakai.log` | Application log file |
| `learned_patterns.json` | Auto-learned attack patterns |
| `geoip/GeoLite2-Country.mmdb` | GeoIP database (optional) |

## Logs

KobraKai logs to `/opt/kobrakai/kobrakai.log`. Example entries:

```
2025-01-10 12:34:56 - WARNING - BLOCKED: 185.234.xxx.xxx - No matching endpoint found
2025-01-10 12:35:01 - WARNING - BLOCKED: 45.155.xxx.xxx - Geo-blocked: RU
2025-01-10 12:35:15 - WARNING - BLOCKED: 193.32.xxx.xxx - Scanner User-Agent detected: friendly-scanner
2025-01-10 12:36:22 - WARNING - BLOCKED: 91.240.xxx.xxx - HONEYPOT: Invalid extension 9999
```

## Managing Blocked IPs

### View Blocked IPs
```bash
python3 /opt/kobrakai/kobrakai.py --list-blocked
```

### Unblock an IP
```bash
# Remove from KobraKai's list
python3 /opt/kobrakai/kobrakai.py --unblock 1.2.3.4

# Also remove from iptables
sudo iptables -D INPUT -s 1.2.3.4 -j DROP
```

### View iptables Rules
```bash
sudo iptables -L INPUT -n | grep KobraKai
```

## Troubleshooting

### KobraKai won't start
- Check permissions: `sudo chown -R root:root /opt/kobrakai`
- Check log file exists: `ls -la /var/log/asterisk/full`
- Run in debug mode: `python3 kobrakai.py --debug`

### Legitimate users getting blocked
1. Add their IPs to `ignore_ips.txt`
2. Add their extensions to `extensions.json`
3. Unblock them: `python3 kobrakai.py --unblock IP`

### Geo-blocking not working
1. Check database exists: `ls -la /opt/kobrakai/geoip/`
2. Verify config: `"geoip_enabled": true`
3. Install geoip2: `pip install geoip2`

### High CPU usage
- Increase `poll_interval` in config (default: 0.1 seconds)
- Check log file size isn't excessive

## Security Considerations

- Always keep `127.0.0.0/8` in the whitelist
- Add your server's own IP to `ignore_ips.txt`
- Add your VoIP provider's IPs to `ignore_ips.txt`
- Test thoroughly before enabling in production
- Monitor logs for false positives initially

## How It Works

1. **Monitors** the Asterisk log file in real-time
2. **Detects** attack signatures using pattern matching
3. **Analyzes** IP behavior (rate, timing, methods)
4. **Blocks** attackers immediately via iptables
5. **Learns** new patterns over time
6. **Persists** blocks across restarts

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

MIT License - See LICENSE file for details.

## Author

Pietro Casoar - FXPRO

## Acknowledgments

- MaxMind for the free GeoLite2 database
- The Asterisk and FreePBX communities
- Everyone fighting VoIP fraud

---

**Remember:** The best defense is a good offense. Strike first. Strike hard. No mercy.
