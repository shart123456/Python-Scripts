import time
import sys
from termcolor import colored, cprint
import os
import subprocess
from colorama import init, Fore, Back, Style
import keyboard
import inquirer
from tqdm import tqdm
from inquirer.themes import GreenPassion
init(autoreset=True)

keep_going = True

###############################################################################
###Notifications, these notification names are uniqiue to BLS, change as needed
not0='BLS Event Notifications'
not1='BLS_Software_Install'#software being installed on host
not2='BLS_Binary_Padding'#Base64 being used
not3='BLS_timestomp'#touch w/ -a being used to change time field
not4='BLS_firewall_status'#user running systemctl stop uwf.service to being down firewall


def start():
    def completion():
        selection = input('Test Again ? Y or N  ---->   ')
        cprint('selection', 'red')
        if selection == ('y'):
            start()
        else:
            cprint('Goodbye', 'red')
            exit(0)
    notification1 = "BLS Software Install"

    # Defensive Evasion
########################################################################################################################
    def defensive_evasion1():
        cprint('Creating File, Modifying Permissions')
        output1 = subprocess.check_output("touch /tmp/test1.txt; ls -la /tmp", shell=True)
        output2 = subprocess.check_output("chmod 777 /tmp/test1.txt ; ls -la /tmp", shell=True)
        output3 = subprocess.check_output("chown root:root /tmp/test1.txt ; ls -la /tmp", shell=True)
        output4 = subprocess.check_output("chattr +i /tmp/test1.txt ; ls -la /tmp", shell=True)
        output5 = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always chmod", shell=True)
        path = "/tmp/defensive_evasion.txt"
        f = open(path, 'a')
        f.write(output1.decode("utf-8"))
        f.write(output2.decode("utf-8"))
        f.write(output3.decode("utf-8"))
        f.write(output4.decode("utf-8"))
        f.write(output5.decode("utf-8"))
        f.close()

    # Attempting to kill firewall
    def defensive_evasion2():
        cprint("Taking Down Firewall", 'green')
        print()
        print()
        cprint("All output printing to /tmp/defensive_evasion2.txt", 'green')
        cmd_ufw = 'systemctl stop ufw.service'
        cmd = cmd_ufw
        output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        outputb = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always ufw.service", shell=True)
        path = "/tmp/defensive_evasion.txt"
        f = open(path, "a")
        f.write(output.stdout)
        f.write(outputb.decode("utf-8"))
        f.close()
        print("Output:\n\n\n" + output.stdout)
        print("\n\nFile can be found at : " + path)


    # Removing syslog logs
    def defensive_evasion3():
        cprint("Hiding Artifcats", 'green')
        cmd_hide = 'touch /tmp/.test2.txt'
        cmd = cmd_hide
        output8 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        outputb = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always touch", shell=True)
        path = "/tmp/defensive_evasion.txt"
        f = open(path, 'a')
        f.write(output8.stdout)
        f.write(outputb.decode("utf-8"))
        f.close()
        print("Output8:\n\n\n" + output8.stdout)
        time.sleep(1)
        cprint('Test Complete', 'green')

    def defensive_evasion5():
        cprint("Adding Binary Padding to File", 'green')
        time.sleep(1)
        cprint("Adding Binary Padding to Target File", 'green')
        time.sleep(1)
        cprint("Target File --> test3.txt", 'green')
        output10 = subprocess.run("touch /tmp/test3.txt", shell=True)
        output11 = subprocess.check_output("dd if=/dev/zero bs=10 count=10 >> /tmp/test3.txt ", shell=True)
        output12 = subprocess.check_output("ls -la /tmp/test3.txt", shell=True)
        path = "/tmp/defensive_evasion.txt"
        f = open(path, 'a')
        f.write(output11.decode("utf-8"))
        f.write(output12.decode("utf-8"))
        print("Test 4 Complete")

    def defensive_evasion6():
        cprint("Indicator Removal on Host", 'green')
        cprint("Attempting Removal of System Logs", 'green')
        cmd_rm = 'touch /tmp/evil.txt ; rm /tmp/evil.txt'
        cmd = cmd_rm
        output12 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        outputb = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always evil", shell=True)
        path = "/tmp/defensive_evasion.txt"
        f = open(path, 'a')
        f.write(output12.stdout)
        f.write(outputb.decode("utf-8"))
        f.close()
        print("Output12:\n\n\n" + output12.stdout)

    def defensive_evasion7():
        cprint("Installing software on Host --- ")
        time.sleep(3)
        output13 = subprocess.check_output("sudo -S apt install locate", shell=True)
        outputb = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always install", shell=True)
        path = "/tmp/defensive_evasion.txt"
        f = open(path, 'a')
        f.write(output13.decode("utf-8"))
        f.write(outputb.decode("utf-8"))
        f.close()
        print("Test 7 Complete")

    def defensive_evasion8():
        cprint("Stomping access time of File")
        cmd = "touch -a -t touch -a -t 197001010000.00 /var/log/syslog"
        os.system(cmd)


    def defensive_evasion():
        defensive_evasion1()
        defensive_evasion2()
        defensive_evasion3()
        defensive_evasion5()
        defensive_evasion6()
        defensive_evasion7()
        defensive_evasion8()
        cmd = 'clear'
        os.system(cmd)
        cprint("BLS Event Notifications", 'red')
        time.sleep(2)
        cprint(not1,'red')
        time.sleep(2)
        cprint(not2,'red')
        time.sleep(1)
        cprint(not3, 'red')
        time.sleep(1)
        cprint(not4, 'red')
        time.sleep(1)
        cprint("", 'red')
        time.sleep(1)
        cprint("", 'red')
        completion()
########################################################################################################################
    # Modifying .bashrc Requires Sudo Priv
    def persistence2():
        cprint("Running Test 2 --- T1053-Schedule Tasks Using At", 'green')
        cmd_at = 'crontab -l'
        cmd = cmd_at
        output18 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/persistence.txt"
        f = open(path, 'a')
        f.write(output18.stdout)
        print("Output18:\n\n\n" + output18.stdout)
        cprint('Test Complete', 'green')

    def persistence3():
        cprint("Running Test 3 --- T1543-Create/Modify System Process (Auditd)", 'green')
        cmd_cron = 'auditctl -b 1'
        cmd = cmd_cron
        output19 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/persistence.txt"
        f = open(path, 'w')
        f.write(output19.stdout)
        print("Output19:\n\n\n" + output19.stdout)
        cprint('Test Complete', 'green')

    def persistence4():
        cprint("Running Test 4 ---  T1053-Schedule Tasks Using At", 'green')
        output20 = subprocess.check_output('echo hello | at now + 1 minute', shell=True)
        path = "/tmp/persistence.txt"
        f = open(path, 'a')
        f.write(output20.decode("utf-8"))
        print("Output20:\n\n\n" + output20.decode("utf-8"))
        cprint('Test Complete', 'green')

    def persistence5():
        cprint("Running Test 5 ---  T1037-Boot/Logon_Initialization_Script", 'green')
        cmd_bash = 'echo hello_moto >> ~/.bashrc'
        cmd = cmd_bash
        output21 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/persistence.txt"
        f = open(path, 'a')
        f.write(output21.stdout)
        print("Output21:\n\n\n" + output21.stdout)
        cprint('Test Complete', 'green')

    def persistence():
        persistence2()
        persistence3()
        persistence4()
        persistence5()
        print()
        print()
        cprint("BLS Notifications Triggered:\n\n\n", 'red')
        time.sleep(2)
        cprint("BLS_user_add",'red')
        time.sleep(1)
        cprint("BLS_audit_crontab",'red')
        print()
        completion()
########################################################################################################################
    # Discovery
    def discovery1():
        # Printing pwquality.conf
        cprint("Running Test 1 --- T1201-Password Policy Discovery", 'green')
        time.sleep(1)
        output21 = subprocess.check_output("cat /etc/passwd", shell=True)
        output21b = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always passwd", shell=True)
        path = "/tmp/discovery.txt"
        f = open(path, 'a')
        f.write(output21.decode("utf-8"))
        f.write(output21b.decode("utf-8"))
        print("Output21:\n\n\n" + output21.decode("utf-8"))
        print("Output21b:\n\n\n" + output21b.decode("utf-8"))
        cprint('Test Complete', 'green')

    def discovery2():
        #    # Searching for account informtion
        # Change path as needed
        cprint("Running Test 2 --- T1087_Account_Discovery", 'green')
        time.sleep(1)
        output22 = subprocess.check_output("grep x:0: /etc/passwd ", shell=True)
        output22b = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always passwd", shell=True)
        path = "/tmp/discovery.txt"
        f = open(path, 'a')
        f.write(output22.decode("utf-8"))
        f.write(output22b.decode("utf-8"))
        print("Output22:\n\n\n" + output22.decode("utf-8"))
        print("Output22b:\n\n\n" + output22b.decode("utf-8"))
        cprint('Test Complete', 'green')

    def discovery3():
        cprint('Enumerating Local Files....')
        time.sleep(1)
        output23 = subprocess.check_output("ls -b --group-directories-first", shell=True)
        path = "/tmp/discovery.txt"
        f = open(path, 'a')
        f.write(output23.decode("utf-8"))
        print("Output23:\n\n\n" + output23.decode("utf-8"))
        cprint('Test Complete', 'green')

    def discovery4():
        # Running tcpdump on eth0
        cprint("Running Test 4 ---  T1040 - Network Sniffing", 'green')
        cmd_sniff = 'timeout 2 tcpdump -i enxa4bb6df6be59'
        cmd = cmd_sniff
        output24 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output24b = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always tcpdump", shell=True)
        path = "/tmp/discovery.txt"
        f = open(path, 'a')
        f.write(output24b.decode("utf-8"))
        print("Output24:\n\n\n" + output24.stdout)
        cprint('Test Complete', 'green')

    def discovery5():
        cprint('Running Test 5 ---   T1046 - System Discovery', 'green')
        output25 = subprocess.check_output("time ; getentahosts ; users ; ps", shell=True)
        outputa = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always ps", shell=True)
        outputb = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always time", shell=True)
        outputc = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always users", shell=True)
        path = "/tmp/discovery.txt"
        f = open(path, 'a')
        f.write(output25.decode("utf-8"))
        f.write(outputa.decode("utf-8"))
        f.write(outputb.decode("utf-8"))
        f.write(outputc.decode("utf-8"))
        f.close()

    def discovery():
        discovery1()
        discovery2()
        discovery3()
        discovery4()
        discovery5()
        cmd = 'clear'
        os.system(cmd)
        cprint('BLS Notifications Triggered', 'red')
        time.sleep(5)
        cprint('BLS_network_sniffing', 'red')
        time.sleep(1)
        cprint("BLS_time_use", 'red')
        time.sleep(1)
        cprint('BLS_user_search', 'red')
        time.sleep(1)
        cprint('BLS_process_search', 'red')
        time.sleep(1)
        cprint("", 'red')
        time.sleep(1)
        cprint("", 'red')
        time.sleep(1)
        cprint("", 'red')
        time.sleep(1)
        cprint("", 'red')
        time.sleep(3)
        completion()

    def main():
        discovery()
########################################################################################################################
    # Recon
    def recon1():
        cprint("Running Test 1 ----> T1595_Active_Scanning", 'green')
        cmd_nmap = 'nmap -Pn 172.16.10.1'
        cmd = cmd_nmap
        output29 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/recon.txt"
        f = open(path, 'a')
        f.write(output29.stdout)
        cprint('Test Complete', 'green')

    def recon2():
        cprint("Running Test 2 ----> T1590_Gathering_Victim_Network_Information", 'green')
        cmd_lookup = 'nslookup blacklanternsecurity.com'
        cmd = cmd_lookup
        output31 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/recon.txt"
        f = open(path, 'a')
        f.write(output31.stdout)
        cprint('Test Complete', 'green')

    def recon3():
        cprint("Running Test 3 ----> Victim DNS Information", 'green')
        cmd_dig = 'dig 172.16.10.1'
        cmd = cmd_dig
        output32 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/recon.txt"
        f = open(path, 'a')
        f.write(output32.stdout)
        cprint('Test Complete', 'green')

    def recon4():
        cprint("Running Test 4 ----> Gather Victim Host Information:Hardware", 'green')
        cmd_cpu = 'lscpu'
        cmd = cmd_cpu
        output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/recon.txt"
        f = open(path, 'a')
        f.write(output.stdout)
        cprint('Test Complete', 'green')

    def recon():
        recon1()
        recon2()
        recon3()
        recon4()
        print()
        cmd = "clear"
        os.system(cmd)
        time.sleep(3)
        cprint('BLS Notifications Triggered', 'red')
        time.sleep(2)
        cprint('BLS_nmap_use', 'red')
        time.sleep(2)
        cprint("BLS_nslookup", 'red')
        time.sleep(2)
        cprint('BLS_lscpu_usage', 'red')
        time.sleep(2)
        completion()

    def main():
        recon()

#######################################################################################################################

    def credential_access1():
        # Access /etc/shadow
        cprint("Running Test 1 ---> T1003-access to /etc/shadow", 'green')
        time.sleep(3)
        cmd_access = 'cat /etc/shadow'
        cmd = cmd_access
        output33 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/credential_acces.txt"
        f = open(path, 'a')
        f.write(output33.stdout)
        print("Flag1:\n\n\n" + output33.stdout)
        cprint('Test Complete', 'green')

    def credential_access3():
        cprint("Running Test 2 ---->  T1552 - Gathering Victim Bash History", 'green')
        time.sleep(2)
        # Getting bash history, sudo needed
        cmd_bash = 'cat ~/.bash_history'
        cmd = cmd_bash
        output34 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/credential_acces.txt"
        f = open(path, 'a')
        f.write(output34.stdout)
        print("Flag2:\n\n\n" + output34.stdout)
        cprint('Test Complete', 'green')

    def credential_access4():
        # Running tcpdump on eth0
        cprint('Running Test 3 ----> T1040 - Packet Capture', 'green')
        time.sleep(1)
        cmd_tcpdump = 'tcpdump -c 5 -nnni enxa4bb6df6be59'
        cmd = cmd_tcpdump
        output35 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/credential_acces.txt"
        f = open(path, 'a')
        f.write(output35.stdout)
        print("Flag3:\n\n\n" + output35.stdout)
        cprint('Test Complete', 'green')

    def credential_access5():
        # Keylogging
        cprint('Running Test 3 ----> T056 - Keylogging', 'green')
        time.sleep(1)
        cmd_keylog = 'echo "$(date +"%d/%m/%y %H:%M:%S.%s") $USER $BASH_COMMAND" >> /tmp/keylog.log ; echo "Hello BLS"'
        cmd = cmd_keylog
        output1 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/credential_acces.txt"
        f = open(path, 'a')
        f.write(output1.stdout)
        print(":\n\n\n" + output1.stdout)
        cprint('Test Complete', 'green')

    def credential_access6():
        cprint('Running Test 5 ----> T1552 Discovery of Private Keys', 'green')
        cmd_keys = 'find /home/blssa -name id_rsa'
        cmd = cmd_keys
        output36 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/credential_acces.txt"
        f = open(path, 'a')
        f.write(output36.stdout)
        print("Flag4:\n\n\n" + output36.stdout)
        cprint('Test Complete', 'green')

    def credential_access7():
        cprint('Running Test 6 --->  T1555 - Credentials From Web Browsers', 'green')
        cmd_tcpdump = 'tcpdump -c 5 -nnni enxa4bb6df6be59'
        cmd = cmd_tcpdump
        output35 = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        path = "/tmp/credential_acces.txt"
        f = open(path, 'a')
        f.write(output35.stdout)
        print("Flag3:\n\n\n" + output35.stdout)
        cprint('Test Complete', 'green')

    def credential_access():
        credential_access1()
        credential_access3()
        credential_access4()
        credential_access5()
        credential_access6()
        # credential_access7()
        cmd = "clear"
        os.system(cmd)
        time.sleep(3)
        cprint('BLS Notifications Triggered', 'red')
        time.sleep(1)
        cprint('BLS_auditd_shadow_access', 'green')
        time.sleep(1)
        cprint("BLS_audit_bash_history", 'green')
        time.sleep(1)
        cprint('BLS_auditd_network_sniffing', 'green')
        time.sleep(1)
        cprint('BLS_auditd_find_usage', 'green')
        time.sleep(1)
        cprint('BLS_auditd_keyloging', 'green')
        time.sleep(1)
        cprint('Credentials From Web Browsers', 'green')
        time.sleep(1)
        completion()

    def main():
        credential_access()

#######################################################################################################################
    # collection
    def collection1():
        # Archive Via Utility
        cprint('Test 1 ---> T1560 Archive via Utility')
        time.sleep(3)
        outputa = subprocess.run("touch /tmp/utility.txt", shell=True)
        outputb = subprocess.run("nano /tmp/utility.txt ; a b c d e f g ", shell=True)
        outputc = subprocess.run("zip --password '123456' /tmp/utility.txt", shell=True)
        #outputd = subprocess.run("echo '123456' | gpg --batch --yes --passphrase-fd 0 --output /tmp/utility.zip.gpg -c /T1560.zip.gpg -c /tmp/utility.zip", shell=True)
        path = "/tmp/collection.txt"
        f = open(path, 'a')
        f.close()
        print("Test 7 Complete")


    def collection2():
        cprint('Test 2 ---> T1123 Audio Capture')
        time.sleep(3)
        outputa = subprocess.run("arecord -d 5 -f U8 > /tmp/audio.txt", shell=True)
        outputb = subprocess.run("gzip /tmp/audio.txt", shell=True)
        path = "/tmp/collection.txt"
        f = open(path, 'a')
        f.close()
        cprint('Test Complete', 'red')


    def collection3():
        cprint('Test 3 ---> T1123 Screen Capture')
        cmd = 'screendump -x > /tmp/touch.txt'
        os.system(cmd)
        time.sleep(3)
        cprint('Test Complete', 'red')

    def collection():
        collection1()
        collection2()
        collection3()
        cmd = "clear"
        os.system(cmd)
        output = subprocess.check_output("cat /var/log/audit/audit.log", shell=True)
        path = "/tmp/collection.txt"
        f = open(path, 'a')
        f.write(output.decode("utf-8"))
        f.close()
        cprint('Test Complete', 'green')
        time.sleep(3)
        cprint('BLS Notifications Triggered', 'red')
        time.sleep(1)
        cprint('BLS_zip_usage', 'red')
        time.sleep(1)
        cprint("BLS_arecord_usage", 'red')
        time.sleep(1)
        cprint("BLS_screendump", 'red')
        time.sleep(1)
        completion()

    def main():
        collection()

    def execution1():
        cprint('Flag 1 Running Test 6 --->  T1059 - Command and Scripting', 'green')
        cmd = 'cd /tmp ; sudo -S bash evil.sh > /tmp/execution.txt'
        os.system(cmd)
        cprint('Test Complete', 'green')

    def execution():
        execution1()

        # impact
#######################################################################################################################
    def impact1():
        # Data Destruction
        print('T1485-Data Destruction')
        cmd = 'dd of=/home/blssa/Desktop/test.txt if=/dev/zero count=100'
        os.system(cmd)
        output = subprocess.check_output("cat /var/log/audit/audit.log | grep --color=always dd", shell=True)
        path = "/tmp/impact.txt"
        f = open(path, 'a')
        f.write(output.decode("utf-8"))
        f.close()

    def impact2():
        # Data Destruction
        print('T1485-Data Destruction')
        cmd = 'sudo -S useradd booboo'
        os.system(cmd)
        cmd1 = 'sudo -S userdel booboo'
        os.system(cmd1)
        output = subprocess.run("cat /var/log/audit/audit.log | grep --color=always user", shell=True)
        path = "/tmp/impact.txt"
        f = open(path, 'a')
        f.write(output.stdout)
        f.close()

    def impact3():
        # Data Destruction
        print('T1496-Resource Hijacking')
        cmd = 'yes man page'
        os.system(cmd)
        exit()

    def impact():
        impact1()
        impact2()
        impact3()
        cmd = "clear"
        os.system(cmd)
        time.sleep(3)
        cprint("BLS Notifications Triggered",'red')
        time.sleep(1)
        cprint("BLS_dd_usage",'red')
        time.sleep(1)
        cprint("BLS_user_add", 'red')
        time.sleep(1)
        cprint("BLS_user_del", 'red')
        completion()
#######################################################################################################################
    def exfiltration1():
        print("Data Transfer Size Limits")
        cmd = "cd /tmp ; touch lilevil.txt"
        os.system(cmd)
        path = "/tmp/lilevil.txt"
        f = open(path, "a")
        f.write("This is the message 4 ever ")
        f.close()
        output = subprocess.run("cd /tmp ; split -b 5 lilevil.txt | pwd", shell=True)


    def exfiltration():
        exfiltration1()
        cmd = "clear"
        os.system(cmd)
        time.sleep(3)
        cprint("BLS Notifications Triggered", 'red')
        time.sleep(1)
        cprint("BLS_split_usage", 'red')
        time.sleep(1)
        cprint("", 'red')
        time.sleep(1)
        cprint("", 'red')
        completion()

########################################################################################################################

    def privilege_escalation1():
        #Sudo Enumeration
        cmd = "sudo -l ; sudo -S cat /etc/sudoers"
        output = subprocess.run(cmd, shell=True)

    def privilege_escalation2():
        #Shell configuration / modification
        cmd = "echo Hello Moto >> ~/.bashrc"
        output = subprocess.run(cmd, shell=True)

    def privilege_escalation():
        privilege_escalation1()
        privilege_escalation2()
        completion()




    category = [Fore.GREEN + 'Defensive_Evasion', Fore.GREEN + 'Persistence', Fore.GREEN + 'Discovery', Fore.GREEN + 'Recon', Fore.GREEN + 'Credential_Access',
                Fore.GREEN + 'Collection', Fore.GREEN + 'Execution', Fore.GREEN + 'Impact', Fore.GREEN + 'Exfiltration', Fore.GREEN + 'Privilege_Escalation']

    loop = tqdm(total=300000, position=0, leave=False)
    for k in range(300000):
        loop.set_description("Collecting System Information".format(k))
        loop.update(2)
    loop.close()

    print(Fore.GREEN + "                                       Target System Information\n")
    time.sleep(1)
    cmd = 'head -2 /etc/os-release'
    os.system(cmd)
    time.sleep(1)

    cmd1 = 'ip -br -c a | grep tun0'
    os.system(cmd1)
    time.sleep(1)

    cmd2 = 'lscpu | grep Architecture'
    os.system(cmd2)
    time.sleep(1)

    cmd3 = 'lscpu | grep Model'
    os.system(cmd3)
    time.sleep(1)

    cmd4 = 'lscpu | grep Vendor'
    os.system(cmd4)
    time.sleep(1)
    print()
    print()

    loop = tqdm(total=200000, position=0, leave=False)
    for k in range(200000):
        loop.set_description("Loading M.A.S.S".format(k))
        loop.update(2)
    loop.close()

    cprint('                                           Mitre Attack Vectors', 'red')

    time.sleep(1)
    print()
    for count, category in enumerate(category):
        print(count, category)
    print()
    choice = input(Fore.RED + "Enter Category -------->     ")
    print()

    if choice == ("0"):
        cprint('                                        Defensive_Evasion', 'green')
        print()
        print()
        defensive_evasion()
    elif choice == ("1"):
        cprint("                                        Persistence Module", 'green')
        persistence()
    elif choice == ("2"):
        cprint("                                        Discovery Module", 'green')
        discovery()
    elif choice == ("3"):
        cprint("                                        Recon Module", 'green')
        recon()
    elif choice == ("4"):
        cprint("                                        Credential Access Module", 'green')
        credential_access()
    elif choice == ("5"):
        cprint("                                        Collection", 'green')
        collection()
    elif choice == ("6"):
        cprint("                                        Execution", 'green')
        execution()
    elif choice == ("7"):
        cprint("                                        Impact", 'green')
        impact()
    elif choice == ("8"):
        cprint("                                        Exfiltration", 'green')
        exfiltration()
    elif choice == ("9"):
        cprint("                                        Privilege_Escalation", 'green')
        privilege_escalation()



while keep_going:
    print(Fore.GREEN + "                                             M.A.S.S")
    start()
