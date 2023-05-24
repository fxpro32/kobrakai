########################################################################################################################################################
########################################################################################################################################################
########################## KobraKai - No Mercy Hacker Blocker for FreePBX Machines - By FXPRO with help from Chat GPT-4 ################################
########################################################################################################################################################
# This software is a no nonsense blocker against hackers that attempt brute force attacks on your FreePBX(c) (Or Asterisk(c) / Sangoma(cc)) devices.   #
# Note that this software is NOT meant for noobs/novices, you need to know what you are doing around a linux system and have at least basic knowledge  #
# of iptables.  When in doubt, how to work with IP Tables, you can always consult Chat GPT for assistance.                                             #
########################################################################################################################################################
########################################################################################################################################################
# You are Free to distribute and edit/add to this script anywhere, with the caveat that you keep my name as the original author of this script         #
# KobraKai - VoIP Hacker Blocker Script                                                                                                                #
# Copyright (c) 2023 FXPRO                                                                                                                             #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  #
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER   #
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS #
# IN THE SOFTWARE. USE AT YOUR OWN RISK.                                                                                                               #
########################################################################################################################################################
#                                                                                                                                                      #
# NOTE: DEBUG Feature should be with the following usage: [python3 kobrakai-v1.py --debug]                                                             #
#                                                                                                                                                      #
# This software has been tested & designed to run continuously on a FreePBX image with great success, blocking all scumbag hackers that were detected  #
# The software has been tested on a Raspberry Pi 4 Hardware / FreePBX image as of May 15 2023.                                                         #
#                                                                                                                                                      #
# In Summary: when a VoIP hacker tries to brute force attack your machine which can ultimately result in having your bandwidth or even account minutes #
# stolen, this software will immediately identify and mercilessly block all IP Addresses of these low life hackers, by applying it to iptables rules   #
# and immediately saving iptables rules.  Even if your machine reboots or has a power failure, when it boots up again, it will automatically be        #
# running in the background and continue to block all hackers from brute force attacking your FreePBX machine.                                         #
#                                                                                                                                                      #
# Just be aware to make sure you add your own IP Address and or Dyns Domain Name, BEFORE you activate the service, so that you don't block yourself    #
# incase you make an error with the SIP / IAX extension or password, otherwise this software will immediately and permanently lock you out of your     #
# system, without mercy.                                                                                                                               #
#                                                                                                                                                      #
# If however, that does happen, you must log in locally to the server and perform the following 2 actions:                                             #
# 1/ Edit the "hacker-ips-list.txt" file and remove your IP Address.                                                                                   #
# and                                                                                                                                                  #
# 2/ Use the "iptables -D INPUT -s {ip} -j DROP" command to remove your ip address from IPTABLES.                                                      #
# and                                                                                                                                                  #
# 3/ Add your IP Address / range to the "ignore-list.txt" file and save.                                                                               #
# Note: {ip} = your IP Address (either local or external or both), depending on what result you get after issuing the "iptables -L -v" command.        #
#                                                                                                                                                      #
# To avoid the above mentioned, make sure you add your IP Address (Local & External / DynDns) to the "ignore-list.txt" file BEFORE executing the code  #
########################################################################################################################################################

# Initiate Modules
import re
import os
import subprocess
import collections
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--debug", help="turn on debug mode", action="store_true")
parser.add_argument("--range", help="block the entire IP range", action="store_true")
args = parser.parse_args()

# Configure the watchdog logging module based on command line argument
if args.debug:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.ERROR)

ASTERISK_LOG_FILE = "/var/log/asterisk/full"
IGNORE_LIST_FILE = "/home/KobraKai/ignore-list.txt"
HACKER_IPS_LIST_FILE = "/home/KobraKai/hacker-ips-list.txt"

blocked_ips = set()
# Additional Blocked IPs iptables Save function here #
# Add the new functions here
def save_iptables():
    # Save the iptables rules
    os.system("iptables-save > /etc/iptables.up.rules")

def load_iptables():
    # Load the iptables rules
    os.system("iptables-restore < /etc/iptables.up.rules")

def check_hacker_ips():
    with open(HACKER_IPS_LIST_FILE, 'r') as f:
        hacker_ips = set(f.read().splitlines())
    iptables_list = str(subprocess.check_output("iptables -L INPUT -v -n", shell=True))
    for ip in hacker_ips:
        if ip not in iptables_list:
            update_iptables(ip, 'A')
### Closed Editing of original here ###

def update_iptables(ip, action):
    print(f"Updating iptables for {ip} with action {action}")
    # Modify IP to block range if --range argument is provided
    if args.range:
        ip = '.'.join(ip.split('.')[:2]) + '.0.0/16'
    # Update iptables rule
    cmd = f"iptables -{action} INPUT -s {ip} -j DROP"
    try:
        output = subprocess.check_output(cmd, shell=True)
        print(f"Executed command: {cmd}")
        print(f"Output: {output}")
        save_iptables()
    except Exception as e:
        print(f"Failed to execute command: {cmd}")
        print(f"Error: {e}")

def process_log_line(line):
    patterns = [
        r"failed for '(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
        r"UDP (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):"
    ]
    ip = None

    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            ip = match.group(1)
            print(f"Suspicious IP Detected: {ip}")
            break

    if ip:
        with open(IGNORE_LIST_FILE, 'r') as f:
            ignore_ips = set(f.read().splitlines())

        with open(HACKER_IPS_LIST_FILE, 'r+') as f:
            hacker_ips = set(f.read().splitlines())

            if ip not in ignore_ips:
                if ip not in blocked_ips:
                    blocked_ips.add(ip)
                    f.write(f"{ip}\n")
                    print(f"Suspicious IP Blocked: {ip}")
                    update_iptables(ip, 'A')  # Append rule
            elif ip in blocked_ips:
                print(f"Removed from IPTABLES: {ip}")
                blocked_ips.remove(ip)
                f.seek(0)
                f.write('\n'.join(hacker_ips))
                f.truncate()
                update_iptables(ip, 'D')  # Delete rule

class AsteriskLogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == ASTERISK_LOG_FILE:
            with open(event.src_path, 'r', encoding='latin-1') as f:
                lines = collections.deque(f, 100)
                for line in lines:
                    process_log_line(line)

if __name__ == "__main__":
    load_iptables()  # Load iptables config and blocked ip list
    check_hacker_ips()  # Check all ips in the hacker-ips-list.txt against iptables config
    event_handler = AsteriskLogHandler()
    observer = Observer()
    observer.schedule(event_handler, path='/var/log/asterisk/', recursive=False)
    observer.start()
    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# END OF CODE
