kobrakai Readme
KobraKai - No Mercy Hacker Blocker for FreePBX Machines - By FXPRO with help from Chat GPT-4

This software is a no nonsense blocker against hackers that attempt brute force attacks on your FreePBX (Or Asterisk / Sangoma) devices.
Note that this software is NOT meant for noobs/novices, you need to know what you are doing around a linux system and have knowledge of iptables.

You are Free to distribute this script anywhere, with the caveat that you keep my name as the original author of this script
KobraKai - VoIP Hacker Blocker Script
Copyright (c) 2023 FXPRO
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE. USE AT YOUR OWN RISK.

NOTE: DEBUG Feature should be with the following usage: [python3 kobrakai-v1.py --debug]

This software has been tested and running continuously on a FreePBX image (Raspberri pi 4) with great success, block all those scumbag hackers

In Short, when an asshole VoIP hacker tries to brute force attack your machine which can ultimately result in having your bandwidth or even minutes
stolen, this software will immediately identify and mercilessly block the IP Addresses of these low life scumbag hackers, by applying it to iptables
rules and saving iptables, within a couple of seconds.

Even if your machine reboots or has a power failure, when it boots up again, it will automatically be running in the background and
continue to block all hackers from brute force attacking your FreePBX machine.

Just be aware to make sure you add your own IP Address and or Dyns Domain Name, BEFORE you activate the service, so that you don't block yourself
incase you make an error with the SIP / IAX extension or password, otherwise this software will immediately and permanently lock you out of your
system, without mercy.

If however, that happens to you, you must log in locally to the server and perform 2 actions:
1/ You must edit the "hacker-ips-list.txt" file and remove your IP Address.
and
2/ Use the "iptables -D INPUT -s {ip} -j DROP" command to remove your ip address from IPTABLES.
Note: {ip} = your IP Address (either local or external or both), depending on what result you get after issuing the "iptables -L -v" command.

To avoid the above mentioned, make sure you add your IP Address (Local & External / DynDns) to the "ignore-list.txt" file before executing the code


Description:

This script is designed to monitor an Asterisk server's log file for suspicious activities and respond by updating the server's iptables rules to block IP addresses identified as suspicious. The script uses the watchdog module to monitor the log file for changes, and it employs regular expressions to identify suspicious activities by their patterns in the log file.

Here's a high-level breakdown of the functions:

save_iptables(): Saves the current iptables rules to a file. This is used after updating the iptables rules to ensure the changes persist after a system reboot.

load_iptables(): Loads the iptables rules from a file. This is used at the start of the script to ensure any previously saved rules are applied.

check_hacker_ips(): Checks if the IPs in the hacker-ips-list.txt file are blocked in the iptables. If any IP is not blocked, the function calls update_iptables to block it.

update_iptables(ip, action): Updates the iptables rules to either block (action='A') or unblock (action='D') the specified IP address, and then saves the updated rules using save_iptables().

process_log_line(line): Processes each line of the log file, looking for patterns that indicate suspicious activity. If a suspicious IP is found and it's not in the ignore list, the function updates the hacker-ips-list.txt file and the iptables rules to block it. If an IP in the ignore list is currently blocked, the function updates the hacker-ips-list.txt file and the iptables rules to unblock it.

AsteriskLogHandler(FileSystemEventHandler): This class is a custom file system event handler. It overrides the on_modified method to process the last 100 lines of the log file whenever the log file is modified.

The script begins by loading the iptables rules and checking the hacker-ips-list.txt file against the iptables. It then starts the file system observer to monitor the Asterisk log file. The script runs in an infinite loop until it's interrupted by the [systemctl stop kobrakai.service] command, at which point it stops the file system observer.

For debug purposes, before enabling and starting the service, you can run the script by issuing the following command:
python3 /home/KobraKai/kobrakai-v1.py --debug
this will allow you to monitor the software to confirm its functionality.

Note that this file is provided with a list of IP Addresses that are known to be used by scumbag VoIP hackers seeking to steal your bandwidth and use your VoIP accounts which you will ultimately pay for out of your own pocket. "I speak from experience"

Now that thats out of the way, Lets get started:

[Note that these instructions are based on linux based machines such as the FreePBX Image for the Raspberry Pi found here: http://www.raspberry-asterisk.org/downloads/]

To make this code run, you need to do the following in preparation:

1/ Get yourself a copy of FileZilla or WinSCP.
2/ Make sure you have 1 folder named "KobraKai" (containing 3 files) (a) "hacker-ips-list.txt" (b) "ignore-list.txt"  (c) "kobrakai-v1.py"
3/ Make sure you have 1 file named "kobrakai.service"
4/ Make sure you have ssh ROOT access to the FreePBX machine.

5/ Next, log into your server (the machine you've installed your FreePBX on via your FileZilla or WinSCP.  In this case it is the Raspberry Pi 4) but make sure you log in via ROOT !!!
### IF YOU DO NOT DO THIS IN ROOT, NOTHING WILL WORK !!! ###  You will need to use the following protocol to transfer files [sftp://x.x.x.x]

6/ Transfer the folder [KobraKai] and ALL its contents, to the /home directory of the FreePBX machine, whilst in root access.

7/ Then transfer the [kobrakai.service] file to the "/etc/systemd/system/" directory of the FreePBX machine, whilst in root access.

8/ Next, use your linux terminal from another machine (or locally on the FreePBX machine), to enter via ssh.
Note if you have not changed the ssh port number, the default will be 22.  It is advised you change this port number to something different and very high in number, above 65,000.

[From linux terminal] type(without the hash#): #ssh root@{server-ip} -p 22
and then type the default/your root password for your machine. Default password= raspberry

[From FreePBX terminal] type(without the hash#): #root
and then type the default/your root password for your machine. Default password= raspberry

Once you have logged in, you must type the following to install the required applications.

Type: (without the hash #)
# apt update

then type
# apt install python3-pip

and then type
# pip3 install watchdog

and finally, type
# apt install netfilter-persistent

Wait for these to install correctly with no errors.
Note that without these 3 apps, the script will not work.

9/ Once that is done, we need to perform the final steps in preparation before running the script and that is we need to now prepare IPTABLES to be able to save rules and have then readily available for the script to read.
Using your ssh terminal (or local terminal) from root prompt (because you must have root privileges): (without the hash #)

# touch /etc/iptables.up.rules

Then, you need to ensure that the file is writable:
# chmod u+w /etc/iptables.up.rules

Now, you can manually save the current iptables rules to this file to ensure that everything is working:

# iptables-save > /etc/iptables.up.rules

10/ Now the machine has been prepared and you are ready to activate the script.

Type: (without the hash #)

# systemctl enable kobrakai.service
This will enable the kobrakai service and enable the script to run in the background

# systemctl start kobrakai.service
This starts the kobrakai service

and to check it's operation, you must type:
# systemctl status kobrakai.service

A correct output that doesn't have any errors should look something like this:

root@raspbx:/KobraKai# systemctl status kobrakai.service
------------------------------------------------------------------------------------------------------------------------------------------
● kobrakai.service - KobraKai No Mercy VoIP Hacker Blocker for use with FreePBX (Asterisk/Sangoma) Software
   Loaded: loaded (/etc/systemd/system/kobrakai.service; enabled; vendor preset: enabled)
   Active: active (running) since Sun 2023-05-14 08:20:23 BST; 2s ago
 Main PID: 6551 (python3)
    Tasks: 4 (limit: 4915)
   CGroup: /system.slice/kobrakai.service
           └─6551 /usr/bin/python3 /home/KobraKai/kobrakai-v1.py

May 14 08:20:23 raspbx systemd[1]: Started KobraKai No Mercy Scumbag VoIP Hacker Blocker for use with FreePBX (Asterisk/Sangoma) Software.
------------------------------------------------------------------------------------------------------------------------------------------

To check the service whilst running and any important events, you can use the following:

# journalctl -u kobrakai.service
The output of this will provide a log which looks something like this, if there are no errors (which should be the case if you've done everything described above, correctly)
------------------------------------------------------------------------------------------------------------------------------------------
May 14 07:20:56 raspbx systemd[1]: Stopping KobraKai No Mercy VoIP Hacker Blocker for use with FreePBX (Asterisk/Sangoma) Software...
May 14 07:20:56 raspbx systemd[1]: kobrakai.service: Main process exited, code=killed, status=15/TERM
May 14 07:20:56 raspbx systemd[1]: kobrakai.service: Succeeded.
May 14 07:20:56 raspbx systemd[1]: Stopped KobraKai No Mercy VoIP Hacker Blocker for use with FreePBX (Asterisk/Sangoma) Software.
May 14 08:20:23 raspbx systemd[1]: Started KobraKai No Mercy VoIP Hacker Blocker for use with FreePBX (Asterisk/Sangoma) Software.
------------------------------------------------------------------------------------------------------------------------------------------

In order to exit this log, you just need to press CTRL and C.

If you want to check on the status of the hacker-ips-list.txt file, to see how many or if any new hacker scumbag IP Addresses have been detected and logged, just use the following command:

# cat /home/KobraKai/hacker-ips-list.txt

Now you can rest easy because your FreePBX machine is protected by an additional firewall process which I have working together with the essential Fail2ban (having set guest access to OFF in the advanced settings of asterisk/freepbx).  I hope this helps anyone who is frustrated or who just doesn't have the time to go through FreePBX settings to make sure everything is locked down, or whoever doesn't have the time or knowledge to protect their system.
You are free to distribute this script, just make sure you retain my name in the top header of the script with the description.

########################################################################################################################################################
The Motivation behind writing this script:
Speaking from experience... what motivated me to make this script is the fact that in the past, I had to pay Internode for a hacking attack that they should have blocked, but they didn't (as a request from me to block all international calls was ignored by Internode) thus resulting in a several thousand dollar bill from an attack that lasted no longer than 5 minutes.  All the complaining in the world didn't resolve the issue, even a complaint to the Communications Ombudsman didn't resolve anything (because the ombudsman is run by the communcations industry, thus protecting their own backs and shafting normal customers/end users).
Therefore in order to AVOID such instances, the best way forward was to protect myself and others, by publishing this script for free to use by anyone that runs their own FreePBX machine, be it on a server or a simple Raspberry Pi.  My use is peronal use between family members, however this script can also be used in corporate scenarios, given the right preparation is made and significant testing between VoIP clients is made, ensuring no wrong extension numbers or wrong passwords are used on each voip client, locally or externally.
Although I do not endorse any VoIP provider, I will however, state that my experience with Internode was abysmal and extremely disgraceful seeing that because I did not remember the exact date I called Internode support (because during that time i was using several different telephones/numbers, I was unable to find the call log) and thus Internode claimed that I didn't call them, when infact I did.

Some rational and logical steps for you are as follows:
(I am not a solicitor/lawyer and this is not legal advice)

1/ NEVER speak on the telephone with your voip provider when you have a complaint.
2/ ALWAYS send an EMAIL to make a complaint, and call them immediately after to confirm they have received the email.  If they haven't received it, then send it again and don't get off the phone until they confirm they have received it.
3/ ALWAYS keep a paper trail when you speak to telephone companies, they have a lot of tricks they use to get out of paying for their mistakes, so a paper trail will mitigate that greatly.
4/ ALWAYS protect yourself by utilizing as many protective measures as possible, which include iptables (when on linux based machines) as well as other firewalls etc...
5/ If you don't make international phone calls, ask your VoIP provider to DISABLE international calls on your account, so you don't get surprises.
6/ If you Do make international phone calls, the best way to mitigate huge hacking surprises, just incase they do manage to get through your firewall, is to ask your VoIP provider to DISABLE ALL SATELLITE CALL DESTINATIONS.
Note that Satellite calls are usually in the range of $10 per minute and when a hacking run is made on your machine, there can be several hundred satellite calls filtered through your VoIP account and after 5 minutes, you can easily see why and how your phone bill can arrive in the thousands.
########################################################################################################################################################
