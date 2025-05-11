#!/usr/bin/env python3
# Filename: kobrakai-utils.py
##########################################################################
# ░█░█░█▀█░█▀▄░█▀▄░█▀█░█░█░█▀█░▀█▀░░░█░█░▀▀▄░░░░░░░░░█░█░▀█▀░▀█▀░█░░░█▀▀ #
# ░█▀▄░█░█░█▀▄░█▀▄░█▀█░█▀▄░█▀█░░█░░░░▀▄▀░▄▀░░░░▄▄▄░░░█░█░░█░░░█░░█░░░▀▀█ #
# ░▀░▀░▀▀▀░▀▀░░▀░▀░▀░▀░▀░▀░▀░▀░▀▀▀░░░░▀░░▀▀▀░░░░░░░░░▀▀▀░░▀░░▀▀▀░▀▀▀░▀▀▀ #
#  KobraKai Utilities - Support tools for KobraKai VoIP Hacker Blocker   #
##########################################################################
#                       Version 2.0 (11-05-2025)                         #
##########################################################################

"""
This utility script provides helper tools for managing the KobraKai VoIP Hacker Blocker.
It includes commands for:
- Analyzing the IP block list
- Exporting formatted lists for firewall configuration
- Testing regex patterns against log samples
- Managing the ignore and watch lists
- Diagnosing system issues

Usage: python3 kobrakai-utils.py [command] [options]
"""

import os
import re
import sys
import json
import argparse
import subprocess
import ipaddress
from datetime import datetime, timedelta

# Default file paths
DEFAULT_CONFIG_PATH = "/home/KobraKai/kobrakai-config.json"
DEFAULT_HACKER_IPS_PATH = "/home/KobraKai/hacker-ips-list.txt"
DEFAULT_IGNORE_LIST_PATH = "/home/KobraKai/ignore-list.txt"
DEFAULT_WATCH_LIST_PATH = "/home/KobraKai/watch-list.json"
DEFAULT_LOG_PATH = "/var/log/asterisk/full"


def load_config(config_path=DEFAULT_CONFIG_PATH):
    """Load the KobraKai configuration"""
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        else:
            print(f"Config file not found: {config_path}")
            return None
    except Exception as e:
        print(f"Error loading config: {e}")
        return None


def analyze_ip_list(ip_list_path=DEFAULT_HACKER_IPS_PATH):
    """Analyze the IP block list for patterns and statistics"""
    if not os.path.exists(ip_list_path):
        print(f"IP list file not found: {ip_list_path}")
        return

    try:
        # Load IPs
        with open(ip_list_path, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]

        if not ips:
            print("IP list is empty.")
            return

        # Organize by subnet
        subnets = {}
        for ip in ips:
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                subnet = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                if subnet not in subnets:
                    subnets[subnet] = []
                subnets[subnet].append(ip)
            except ValueError:
                continue

        # Sort subnets by count
        sorted_subnets = sorted(subnets.items(), key=lambda x: len(x[1]), reverse=True)

        # Print statistics
        print(f"Total IPs blocked: {len(ips)}")
        print(f"Total subnets affected: {len(subnets)}")
        print("\nTop 10 subnets by blocked IP count:")
        print("-" * 50)
        print(f"{'Subnet':<18} | {'Count':<8} | {'Sample IPs'}")
        print("-" * 50)

        for i, (subnet, subnet_ips) in enumerate(sorted_subnets[:10]):
            sample = ", ".join(subnet_ips[:3])
            if len(subnet_ips) > 3:
                sample += f", ... ({len(subnet_ips) - 3} more)"
            print(f"{subnet:<18} | {len(subnet_ips):<8} | {sample}")

    except Exception as e:
        print(f"Error analyzing IP list: {e}")


def export_for_firewall(ip_list_path=DEFAULT_HACKER_IPS_PATH, output_format="plain", output_path=None):
    """Export the IP block list in various firewall-compatible formats"""
    if not os.path.exists(ip_list_path):
        print(f"IP list file not found: {ip_list_path}")
        return

    try:
        # Load IPs
        with open(ip_list_path, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]

        if not ips:
            print("IP list is empty.")
            return

        # Generate timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

        # Determine output path
        if not output_path:
            output_path = f"/home/KobraKai/firewall_export_{output_format}_{timestamp}.txt"

        # Generate output based on requested format
        if output_format == "plain":
            # Simple list of IPs
            output = "\n".join(sorted(ips))
        elif output_format == "iptables":
            # IPTables rules
            output = "\n".join([f"iptables -A INPUT -s {ip} -j DROP" for ip in sorted(ips)])
        elif output_format == "cisco":
            # Cisco ACL format
            output = "\n".join([f"deny ip host {ip} any" for ip in sorted(ips)])
        elif output_format == "mikrotik":
            # MikroTik format
            output = "\n".join([f"/ip firewall address-list add list=blocklist address={ip}" for ip in sorted(ips)])
        elif output_format == "subnet":
            # Consolidated subnets (for more efficient blocking)
            subnet_counts = {}
            for ip in ips:
                try:
                    subnet = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                    if subnet in subnet_counts:
                        subnet_counts[subnet] += 1
                    else:
                        subnet_counts[subnet] = 1
                except ValueError:
                    continue

            # Only export subnets with at least 5 IPs
            subnets = [subnet for subnet, count in subnet_counts.items() if count >= 5]
            output = "\n".join(sorted(subnets))
        else:
            print(f"Unknown output format: {output_format}")
            return

        # Write to file
        with open(output_path, 'w') as f:
            f.write(output)

        print(f"Exported {len(ips)} IPs to: {output_path}")

    except Exception as e:
        print(f"Error exporting for firewall: {e}")


def test_regex_patterns(log_path=DEFAULT_LOG_PATH, sample_lines=20):
    """Test regex patterns against recent log entries to verify detection"""
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        return

    # Load configuration to get patterns
    config = load_config()
    if not config:
        return

    all_patterns = []
    for severity in ["severity_high", "severity_medium", "severity_low"]:
        all_patterns.extend([(pattern, severity) for pattern in config["attack_patterns"][severity]])

    # IP extraction patterns
    ip_patterns = [
        r"failed for '(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
        r"from UDP (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
        r"failed for '(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):",
        r"from '(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):"
    ]

    try:
        # Get the last sample_lines lines from the log
        with open(log_path, 'r', encoding='latin-1') as f:
            # Go to the end of file
            f.seek(0, 2)
            file_size = f.tell()

            # Start from the end and read blocks until we have enough lines
            block_size = 4096
            position = file_size
            lines = []

            while len(lines) < sample_lines and position > 0:
                # Move position back by block size
                position = max(position - block_size, 0)
                f.seek(position)

                # Read a block and split into lines
                block = f.read(min(block_size, file_size - position))
                lines = block.splitlines() + lines

            # Take the last sample_lines
            lines = lines[-sample_lines:]

        print(f"Testing patterns against {len(lines)} recent log lines:")
        print("-" * 80)

        # Test each line against each pattern
        matches_found = False
        for i, line in enumerate(lines):
            line_matches = []

            # Try to extract IP
            ip = None
            for pattern in ip_patterns:
                match = re.search(pattern, line)
                if match:
                    ip = match.group(1)
                    try:
                        # Validate IP
                        ipaddress.IPv4Address(ip)
                        break
                    except ValueError:
                        ip = None

            # Check against attack patterns
            for pattern, severity in all_patterns:
                if re.search(pattern, line):
                    line_matches.append((pattern, severity))

            if line_matches:
                matches_found = True
                print(f"Line {i + 1}: {line[:80]}...")
                print(f"  IP detected: {ip}")
                for pattern, severity in line_matches:
                    print(f"  Match: '{pattern}' (Severity: {severity})")
                print("-" * 80)

        if not matches_found:
            print("No pattern matches found in the sample log lines.")
            print("You may need to update the patterns or check more log lines.")

    except Exception as e:
        print(f"Error testing regex patterns: {e}")


def manage_ignore_list(action, ip=None, ignore_list_path=DEFAULT_IGNORE_LIST_PATH):
    """Manage the ignore list (add/remove/list IPs)"""
    try:
        # Ensure the file exists
        if not os.path.exists(ignore_list_path):
            with open(ignore_list_path, 'w') as f:
                pass

        # Load current list
        with open(ignore_list_path, 'r') as f:
            ignore_ips = set(line.strip() for line in f if line.strip())

        if action == "list":
            if ignore_ips:
                print("IPs in ignore list:")
                for ip in sorted(ignore_ips):
                    print(f"  {ip}")
            else:
                print("Ignore list is empty.")

        elif action == "add" and ip:
            # Validate IP
            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                print(f"Invalid IP address: {ip}")
                return

            if ip in ignore_ips:
                print(f"IP {ip} is already in the ignore list.")
            else:
                ignore_ips.add(ip)
                with open(ignore_list_path, 'w') as f:
                    for ignore_ip in sorted(ignore_ips):
                        f.write(f"{ignore_ip}\n")
                print(f"Added {ip} to ignore list.")

        elif action == "remove" and ip:
            if ip in ignore_ips:
                ignore_ips.remove(ip)
                with open(ignore_list_path, 'w') as f:
                    for ignore_ip in sorted(ignore_ips):
                        f.write(f"{ignore_ip}\n")
                print(f"Removed {ip} from ignore list.")
            else:
                print(f"IP {ip} is not in the ignore list.")

        else:
            print(f"Unknown action: {action}")

    except Exception as e:
        print(f"Error managing ignore list: {e}")


def check_system_status():
    """Check the status of the KobraKai system and its dependencies"""
    try:
        print("KobraKai System Status Check")
        print("-" * 40)

        # Check if config file exists
        config_exists = os.path.exists(DEFAULT_CONFIG_PATH)
        print(f"Config file exists: {config_exists}")

        if config_exists:
            config = load_config()
            if config:
                print("Configuration loaded successfully")
            else:
                print("Error loading configuration")

        # Check if IP list and ignore list exist
        hacker_ips_exists = os.path.exists(DEFAULT_HACKER_IPS_PATH)
        ignore_list_exists = os.path.exists(DEFAULT_IGNORE_LIST_PATH)
        watch_list_exists = os.path.exists(DEFAULT_WATCH_LIST_PATH)

        print(f"Hacker IPs list exists: {hacker_ips_exists}")
        print(f"Ignore list exists: {ignore_list_exists}")
        print(f"Watch list exists: {watch_list_exists}")

        # Count blocked IPs
        if hacker_ips_exists:
            with open(DEFAULT_HACKER_IPS_PATH, 'r') as f:
                ip_count = sum(1 for line in f if line.strip())
            print(f"Number of IPs in block list: {ip_count}")

        # Check if log file exists and is readable
        log_exists = os.path.exists(DEFAULT_LOG_PATH)
        log_readable = os.access(DEFAULT_LOG_PATH, os.R_OK) if log_exists else False

        print(f"Asterisk log file exists: {log_exists}")
        print(f"Asterisk log file is readable: {log_readable}")

        # Check IPTables
        try:
            iptables_output = subprocess.check_output("iptables -L INPUT -v -n | grep DROP", shell=True, text=True)
            iptables_lines = iptables_output.splitlines()
            print(f"IPTables DROP rules: {len(iptables_lines)}")
        except subprocess.CalledProcessError:
            print("Error checking IPTables rules")

        # Check system resources
        try:
            # Check disk space
            df_output = subprocess.check_output("df -h /home", shell=True, text=True)
            disk_usage = df_output.splitlines()[1].split()[4]
            print(f"Disk usage: {disk_usage}")

            # Check memory usage
            mem_output = subprocess.check_output("free -m | grep Mem", shell=True, text=True)
            mem_total = mem_output.split()[1]
            mem_used = mem_output.split()[2]
            print(f"Memory usage: {mem_used}M / {mem_total}M")

        except subprocess.CalledProcessError:
            print("Error checking system resources")

    except Exception as e:
        print(f"Error checking system status: {e}")


def main():
    """Main function to parse command line arguments and execute commands"""
    parser = argparse.ArgumentParser(description="KobraKai Utilities")

    # Main command
    parser.add_argument("command", choices=[
        "analyze", "export", "test-regex", "ignore", "status"
    ], help="Command to execute")

    # Options for export command
    parser.add_argument("--format", choices=["plain", "iptables", "cisco", "mikrotik", "subnet"],
                        default="plain", help="Output format for export command")
    parser.add_argument("--output", help="Output file path for export command")

    # Options for ignore command
    parser.add_argument("--action", choices=["add", "remove", "list"],
                        default="list", help="Action for ignore command")
    parser.add_argument("--ip", help="IP address for ignore command")

    # Options for test-regex command
    parser.add_argument("--lines", type=int, default=20,
                        help="Number of recent log lines to test for test-regex command")

    # Parse arguments
    args = parser.parse_args()

    # Execute command
    if args.command == "analyze":
        analyze_ip_list()
    elif args.command == "export":
        export_for_firewall(output_format=args.format, output_path=args.output)
    elif args.command == "test-regex":
        test_regex_patterns(sample_lines=args.lines)
    elif args.command == "ignore":
        manage_ignore_list(args.action, args.ip)
    elif args.command == "status":
        check_system_status()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
