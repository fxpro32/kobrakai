#!/bin/bash
# KobraKai v2.0 Installer Script (UPDATED)
# - Removes kobrakai-utils.py installation and references
# - Updates systemd unit to the new kobrakai.service spec

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_status() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root"
    exit 1
fi

print_status "Starting KobraKai v2.0 Installer"

# Check for existing installation
if [ -f "/etc/systemd/system/kobrakai.service" ]; then
    print_warning "Existing KobraKai service detected. Stopping service before installation."
    systemctl stop kobrakai.service
fi

# Create KobraKai directory
INSTALL_DIR="/home/KobraKai"
if [ ! -d "$INSTALL_DIR" ]; then
    print_status "Creating KobraKai directory at $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
else
    print_warning "KobraKai directory already exists at $INSTALL_DIR"
    print_status "Backing up existing files..."

    # Backup existing files if they exist
    BACKUP_DIR="$INSTALL_DIR/backup_$(date +%Y%m%d%H%M%S)"
    mkdir -p "$BACKUP_DIR"

    # Backup key files
    for file in kobrakai-v1.py kobrakai-v2.py ignore-list.txt hacker-ips-list.txt kobrakai-config.json kobrakai.log; do
        if [ -f "$INSTALL_DIR/$file" ]; then
            cp "$INSTALL_DIR/$file" "$BACKUP_DIR/"
            print_status "Backed up $file to $BACKUP_DIR"
        fi
    done
fi

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
print_status "Found Python $PYTHON_VERSION"

# Install required packages
print_status "Installing required system packages..."
apt-get update
apt-get install -y python3-pip iptables iptables-persistent

# Install required Python packages
print_status "Installing required Python packages..."
pip3 install watchdog

# Check for existing ignore and hacker lists
if [ -f "$INSTALL_DIR/ignore-list.txt" ]; then
    print_status "Existing ignore-list.txt found. Preserving it."
else
    print_status "Creating empty ignore-list.txt"
    touch "$INSTALL_DIR/ignore-list.txt"
fi

if [ -f "$INSTALL_DIR/hacker-ips-list.txt" ]; then
    print_status "Existing hacker-ips-list.txt found. Preserving it."
else
    print_status "Creating empty hacker-ips-list.txt"
    touch "$INSTALL_DIR/hacker-ips-list.txt"
fi

# Create watch list if it doesn't exist
[ -f "$INSTALL_DIR/watch-list.json" ] || touch "$INSTALL_DIR/watch-list.json"

# Create logs directory (optional) and main log file for systemd append
LOGS_DIR="$INSTALL_DIR/logs"
if [ ! -d "$LOGS_DIR" ]; then
    print_status "Creating logs directory at $LOGS_DIR"
    mkdir -p "$LOGS_DIR"
fi

# Ensure main combined log file exists (systemd will append to it)
if [ ! -f "$INSTALL_DIR/kobrakai.log" ]; then
    touch "$INSTALL_DIR/kobrakai.log"
    print_status "Created $INSTALL_DIR/kobrakai.log"
fi

# Check if Asterisk is installed
if [ ! -d "/var/log/asterisk" ]; then
    print_warning "Asterisk logs directory not found at /var/log/asterisk"
    print_warning "KobraKai may not work correctly without Asterisk/FreePBX"
else
    print_status "Asterisk logs directory found at /var/log/asterisk"

    # Check if we can read the log file
    ASTERISK_FULL_LOG="/var/log/asterisk/full"
    if [ ! -f "$ASTERISK_FULL_LOG" ]; then
        print_warning "Asterisk full log file not found at $ASTERISK_FULL_LOG"
    elif [ ! -r "$ASTERISK_FULL_LOG" ]; then
        print_warning "Cannot read Asterisk log file. Adjusting permissions..."
        chmod +r "$ASTERISK_FULL_LOG"
    else
        print_status "Asterisk log file is readable"
    fi
fi

# Create default config
print_status "Creating default configuration..."
cat > "$INSTALL_DIR/kobrakai-config.json" << 'EOL'
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
EOL

# Install the main script
print_status "Installing KobraKai scripts..."

if [ -f "./kobrakai-v2.py" ]; then
    cp ./kobrakai-v2.py "$INSTALL_DIR/kobrakai-v2.py"
    chmod +x "$INSTALL_DIR/kobrakai-v2.py"
    print_status "Installed kobrakai-v2.py from current directory"
else
    print_error "kobrakai-v2.py not found in current directory!"
    print_error "Please make sure the script is in the same directory as the installer"
    exit 1
fi

# NOTE: kobrakai-utils.py is deprecated and no longer installed

# Set correct permissions
chown -R root:root "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

# Create/Update systemd service to the new spec
print_status "Creating systemd service..."
cat > /etc/systemd/system/kobrakai.service << 'EOL'
# /etc/systemd/system/kobrakai.service
[Unit]
Description=KobraKai VoIP Intrusion Blocker
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/KobraKai/kobrakai-v2.py --debug
WorkingDirectory=/home/KobraKai

# Restart behavior
Restart=always
RestartSec=2

# Make stop fast & reliable
KillSignal=SIGINT
KillMode=mixed
TimeoutStopSec=10

# Log straight to your file (no nohup needed)
StandardOutput=append:/home/KobraKai/kobrakai.log
StandardError=append:/home/KobraKai/kobrakai.log

[Install]
WantedBy=multi-user.target
EOL

# Check if there's an existing v1 installation
if [ -f "$INSTALL_DIR/kobrakai-v1.py" ]; then
    print_warning "Detected existing v1 installation"
    print_status "Moving kobrakai-v1.py to backup"
    mv "$INSTALL_DIR/kobrakai-v1.py" "$INSTALL_DIR/kobrakai-v1.py.bak"
fi

# Reload systemd, enable and start service
print_status "Configuring and starting KobraKai service..."
systemctl daemon-reload
systemctl enable kobrakai.service

# Stop any existing service
systemctl stop kobrakai.service 2>/dev/null

# Start the new service
systemctl start kobrakai.service

# Check if the service started successfully
sleep 2
if systemctl is-active --quiet kobrakai.service; then
    print_status "KobraKai service started successfully"
else
    print_error "KobraKai service failed to start. Checking logs..."
    journalctl -u kobrakai.service --no-pager -n 50
    print_error "Please fix the issues and restart the service"
fi

# Set up a cron job to periodically check and restart the service if needed
print_status "Setting up service monitoring via cron..."
(crontab -l 2>/dev/null | grep -v "kobrakai.service"; echo "*/5 * * * * /bin/systemctl is-active --quiet kobrakai.service || /bin/systemctl restart kobrakai.service") | crontab -

# Check for existing iptables rules
print_status "Checking iptables configuration..."
if ! iptables -L INPUT -v -n | grep -q "DROP"; then
    print_warning "No DROP rules found in iptables"
    print_warning "Make sure iptables is properly configured for KobraKai to function"
else
    RULES_COUNT=$(iptables -L INPUT -v -n | grep "DROP" | wc -l)
    print_status "Found $RULES_COUNT DROP rules in iptables"
fi

print_status ""
print_status "======================= INSTALLATION COMPLETE ========================"
print_status ""
print_status "KobraKai v2.0 has been installed to: $INSTALL_DIR"
print_status ""
print_status "█▄▀ █▀█ █▄▄ █▀█ ▄▀█ █▄▀ ▄▀█ █"
print_status "█ █ █▄█ █▄█ █▀▄ █▀█ █ █ █▀█ █"
print_status ""
print_status "CRITICAL: Whitelist your own IPs to prevent lockout:"
print_status "  - Edit /home/KobraKai/ignore-list.txt and add one IP per line"
print_status ""
print_status "Useful commands:"
print_status "  - Check service status: systemctl status kobrakai.service"
print_status "  - View live logs: tail -f /home/KobraKai/kobrakai.log"
print_status "  - Configure settings in: /home/KobraKai/kobrakai-config.json"
print_status ""
print_status "If you have any issues, check the logs in /home/KobraKai/kobrakai.log or via: journalctl -u kobrakai.service"
print_status ""
