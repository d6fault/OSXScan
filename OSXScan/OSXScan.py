import os
from colorama import Fore, Style, Back
import time
import sys


def print_section_header(section_number, title):
    print(f"\n{Fore.BLUE}{'═' * 80}")
    print(f"{Fore.YELLOW}[{section_number}] {title}")
    print(f"{Fore.BLUE}{'═' * 80}{Style.RESET_ALL}\n")

def print_subsection(title):
    print(f"\n{Fore.CYAN}[+] {title}:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{'─' * 40}{Style.RESET_ALL}")

def print_banner():
    print(f"""{Fore.CYAN}                                                                                

                                                   *@@@@@                       
                                               @@@@@@@@@@                       
                                            (@@@@@@@@@@@@                       
                                          *@@@@@@@@@@@@@                        
                                         @@@@@@@@@@@@@,                         
                                        /@@@@@@@@@@@%                           
                                        @@@@@@@@@@                              
                                        ,@@@@,                                  
{Fore.BLUE}                    #@@@@@@@@@@@@@%,           #@@@@@@@@@@@@@@@@,               
                @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,           
             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         
{Fore.MAGENTA}           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         
          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.           
        (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              
{Fore.RED}        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
{Fore.YELLOW}       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
{Fore.GREEN}       *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@             
        /@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           
{Fore.CYAN}         &@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       
          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      
           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       
{Fore.BLUE}            *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        
              @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.         
               (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&           
{Fore.MAGENTA}                 #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@             
                   &@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
                      @@@@@@@@@@@@@@@@*. ....,@@@@@@@@@@@@@@@@*                 
                         *@@@@@@                    @@@@@@/                     """)
    print(f"""{Fore.WHITE}
           ╭─────────────────────────────────────────────────────────────────────╮
           │{Fore.CYAN}                          OSXScan v1.0                               {Fore.WHITE}│
           │{Fore.YELLOW}                     Security Assessment Tool                        {Fore.WHITE}│
           │                                                                     │
           │{Fore.GREEN}              🔒 System Audit  |  🛡️ Vulnerability Scan              {Fore.WHITE}│
           │{Fore.CYAN}              👤 Access Review |  🚦 Security Policies               {Fore.WHITE}│
           ╰─────────────────────────────────────────────────────────────────────╯""")
    print(f"\n{Fore.BLUE}{'═' * 80}\n{Style.RESET_ALL}")

def general_info():
    print(Fore.YELLOW + "\n[*] General Information:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("sw_vers")
    print(Style.RESET_ALL)
    os.system("sysctl -n machdep.cpu.brand_string")
    print(Style.RESET_ALL)
    os.system("id")
    print(Style.RESET_ALL)  
    os.system("whoami")
    print(Style.RESET_ALL)
    os.system("hostname")
    print(Style.RESET_ALL)
    os.system("uname -a")   
    print(Style.RESET_ALL)
    os.system("sysctl -n hw.machine")
    print(Style.RESET_ALL)  
    os.system("sysctl -n hw.model")
    print(Style.RESET_ALL)
    

def system_info():
    print(Fore.YELLOW + "\n[*] System Information:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("system_profiler")
    print(Style.RESET_ALL)
    time.sleep(1)


def check_sudo_access():
    print(Fore.YELLOW + "\n[*] Checking sudo access:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("sudo -n true")
    print(Style.RESET_ALL)
    time.sleep(1)

def sudo_version():
    print(Fore.YELLOW + "\n[*] Sudo Version:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("sudo -V")
    print(Style.RESET_ALL)
    time.sleep(1)

def suid_binaries():
    print(Fore.YELLOW + "\n[*] SUID Binaries:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def sgid_binaries():
    print(Fore.YELLOW + "\n[*] SGID Binaries:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("find / -perm -2000 -type f -exec ls -l {} \; 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def crontab_jobs():
    print(Fore.YELLOW + "\n[*] Cron Jobs:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("crontab -l")
    print(Style.RESET_ALL)
    time.sleep(1)


def login_items():
    print(Fore.YELLOW + "\n[*] System Login Items:")
    print("=" * 80)
    print(Style.RESET_ALL)
    print(Fore.CYAN + "\n[+] LaunchAgents:" + Style.RESET_ALL)
    os.system("ls -la /Library/LaunchAgents")
    print(Fore.CYAN + "\n[+] LaunchDaemons:" + Style.RESET_ALL)
    os.system("ls -la /Library/LaunchDaemons")
    
    print(Fore.YELLOW + "\n[*] User Login Items:")
    print("=" * 80)
    print(Style.RESET_ALL)
    print(Fore.CYAN + "\n[+] User LaunchAgents:" + Style.RESET_ALL)
    os.system("ls -la ~/Library/LaunchAgents")
    print(Fore.CYAN + "\n[+] System Events Login Items:" + Style.RESET_ALL)
    os.system("osascript -e 'tell application \"System Events\" to get the name of every login item'")
    
    print(Fore.YELLOW + "\n[*] Legacy Login Items:")
    print("=" * 80)
    print(Style.RESET_ALL)
    print(Fore.CYAN + "\n[+] StartupItems:" + Style.RESET_ALL)
    os.system("ls -la /Library/StartupItems")
    print(Fore.CYAN + "\n[+] User LoginItems:" + Style.RESET_ALL)
    os.system("ls -la ~/Library/LoginItems")
    print(Style.RESET_ALL)
    time.sleep(1)

def user_accounts():
    print(Fore.YELLOW + "\n[*] User Accounts:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("dscl . list /Users | grep -v '^_'")
    print(Style.RESET_ALL)
    time.sleep(1)

def hidden_users():
    print(Fore.YELLOW + "\n[*] Hidden Users:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("dscl . list /Users | grep '^_'")
    print(Style.RESET_ALL)
    time.sleep(1)

def user_groups():
    print(Fore.YELLOW + "\n[*] User Groups:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("dscl . list /Groups | grep -v '^_'")
    print(Style.RESET_ALL)
    time.sleep(1)

def hidden_groups():
    print(Fore.YELLOW + "\n[*] Hidden Groups:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("dscl . list /Groups | grep '^_'")
    print(Style.RESET_ALL)
    time.sleep(1)

def wheel_group():
    print(Fore.YELLOW + "\n[*] Wheel Group Members:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("dseditgroup -o read wheel")
    print(Style.RESET_ALL)
    time.sleep(1)

def sip_status():
    print(Fore.YELLOW + "\n[*] SIP Status:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("csrutil status")
    print(Style.RESET_ALL)
    time.sleep(1)

def xprotect_status():
    print(Fore.YELLOW + "\n[*] XProtect Status:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("spctl status")
    print(Style.RESET_ALL)
    time.sleep(1)

def gatekeeper_status():
    print(Fore.YELLOW + "\n[*] Gatekeeper Status:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("spctl --status")
    print(Style.RESET_ALL)
    time.sleep(1)   

def firewall_status():
    print(Fore.YELLOW + "\n[*] Firewall Status:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
    print(Style.RESET_ALL)
    time.sleep(1)

def ssh_keys():
    print(Fore.YELLOW + "\n[*] SSH Keys:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la ~/.ssh")
    print(Style.RESET_ALL)
    time.sleep(1)

def network_info():
    print(Fore.YELLOW + "\n[*] Network Information:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ifconfig")
    os.system("netstat -an | grep LISTEN")
    os.system("lsof -i -P | grep LISTEN")
    print(Style.RESET_ALL)
    time.sleep(1)

def security_settings():
    print(Fore.YELLOW + "\n[*] Security Settings:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("defaults read /Library/Preferences/com.apple.security")
    os.system("defaults read /Library/Preferences/com.apple.alf")  #
    os.system("spctl --status")  
    os.system("csrutil status")  
    print(Style.RESET_ALL)
    time.sleep(1)

def installed_software():
    print(Fore.YELLOW + "\n[*] Installed Software:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la /Applications")
    os.system("pkgutil --pkgs")
    os.system("brew list 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_processes():
    print(Fore.YELLOW + "\n[*] Running Processes:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ps aux")
    os.system("launchctl list")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_sharing():
    print(Fore.YELLOW + "\n[*] Sharing Settings:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("sharing -l")
    os.system("systemsetup -getremotelogin")
    os.system("systemsetup -getremoteappleevents")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_bluetooth():
    print(Fore.YELLOW + "\n[*] Bluetooth Status:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("system_profiler SPBluetoothDataType")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_wifi():
    print(Fore.YELLOW + "\n[*] WiFi Information:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I")
    os.system("networksetup -listallhardwareports")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_dns():
    print(Fore.YELLOW + "\n[*] DNS Configuration:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("scutil --dns")
    os.system("cat /etc/resolv.conf")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_ssh():
    print(Fore.YELLOW + "\n[*] SSH Configuration:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la ~/.ssh/")
    os.system("cat /etc/ssh/sshd_config 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_certificates():
    print(Fore.YELLOW + "\n[*] System Certificates:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("security find-certificate -a -p /Library/Keychains/System.keychain")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_tcc_permissions():
    print(Fore.YELLOW + "\n[*] TCC Permissions:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db 'select * from access'")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_kernel_extensions():
    print(Fore.YELLOW + "\n[*] Kernel Extensions:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("kextstat")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_filevault():
    print(Fore.YELLOW + "\n[*] FileVault Status:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("fdesetup status")
    os.system("diskutil apfs list")  # Shows encryption status of APFS volumes
    print(Style.RESET_ALL)
    time.sleep(1)       

def check_mdm():
    print(Fore.YELLOW + "\n[*] MDM (Mobile Device Management) Status:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("profiles status -type enrollment")
    os.system("profiles list")
    print(Style.RESET_ALL)
    time.sleep(1)


def check_time_machine():
    print(Fore.YELLOW + "\n[*] Time Machine Configuration:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("tmutil destinationinfo")
    os.system("tmutil listbackups")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_auto_updates():
    print(Fore.YELLOW + "\n[*] Software Update Settings:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("defaults read /Library/Preferences/com.apple.SoftwareUpdate")
    os.system("softwareupdate --list")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_password_policy():
    print(Fore.YELLOW + "\n[*] Password Policy Settings:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("pwpolicy -getaccountpolicies")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_screen_sharing():
    print(Fore.YELLOW + "\n[*] Screen Sharing Status:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("launchctl list com.apple.screensharing")
    os.system("lsof -i :5900")  # VNC port
    print(Style.RESET_ALL)
    time.sleep(1)

def check_icloud():
    print(Fore.YELLOW + "\n[*] iCloud Configuration:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("defaults read MobileMeAccounts")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_startup_items():
    print(Fore.YELLOW + "\n[*] Additional Startup Items:")
    print("=" * 80)
    print(Style.RESET_ALL)
    print(Fore.CYAN + "\n[+] Global Launch Daemons:" + Style.RESET_ALL)
    os.system("ls -la /System/Library/LaunchDaemons/")
    print(Fore.CYAN + "\n[+] User Login Items:" + Style.RESET_ALL)
    os.system("ls -la ~/Library/Application\\ Support/com.apple.backgroundtaskmanagementagent/")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_quarantine():
    print(Fore.YELLOW + "\n[*] Quarantine Database:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 'select * from LSQuarantineEvent'")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_usb_devices():
    print(Fore.YELLOW + "\n[*] USB Device History:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("system_profiler SPUSBDataType")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_recent_files():
    print(Fore.YELLOW + "\n[*] Recent Files:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la ~/Library/Recent\\ Servers/")
    os.system("ls -la ~/Library/Preferences/com.apple.recentitems.plist")
    print(Style.RESET_ALL)
    time.sleep(1)


def check_sudo_config():
    print(Fore.YELLOW + "\n[*] Sudo Configuration:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("sudo cat /etc/sudoers 2>/dev/null")
    os.system("sudo cat /etc/sudoers.d/* 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_env_paths():
    print(Fore.YELLOW + "\n[*] PATH Environment Variable:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("echo $PATH")
    os.system("ls -la $(echo $PATH | tr ':' ' ')")  # Check permissions of PATH directories
    print(Style.RESET_ALL)
    time.sleep(1)

def check_dyld():
    print(Fore.YELLOW + "\n[*] DYLD Environment:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("echo $DYLD_LIBRARY_PATH")
    os.system("echo $DYLD_INSERT_LIBRARIES")
    os.system("echo $DYLD_FRAMEWORK_PATH")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_shell_configs():
    print(Fore.YELLOW + "\n[*] Shell Configuration Files:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la ~/.bash_profile ~/.bashrc ~/.zshrc ~/.zprofile /etc/profile /etc/bashrc 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)


def check_special_permissions():
    print(Fore.YELLOW + "\n[*] Files with Special Permissions:")
    print("=" * 80)
    print(Style.RESET_ALL)
    print(Fore.CYAN + "\n[+] Checking root-owned files with write access:" + Style.RESET_ALL)
    os.system("find / -uid 0 -perm -0002 -type f -ls 2>/dev/null")
    print(Fore.CYAN + "\n[+] Checking files with owner/group mismatch:" + Style.RESET_ALL)
    os.system("find / -type f -user root -perm -0002 ! -group root -ls 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_cron_permissions():
    print(Fore.YELLOW + "\n[*] Cron Directory Permissions:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la /etc/cron* /etc/crontab /var/spool/cron/crontabs 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_service_binaries():
    print(Fore.YELLOW + "\n[*] Service Binary Permissions:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la /Library/LaunchDaemons/* /System/Library/LaunchDaemons/* 2>/dev/null")
    os.system("ls -la /Library/StartupItems/* /System/Library/StartupItems/* 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_weak_apps():
    print(Fore.YELLOW + "\n[*] Applications with Weak Permissions:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("find /Applications -perm -2 -type f -ls 2>/dev/null")
    os.system("find /Applications -perm -20 -type f -ls 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_admin_applications():
    print(Fore.YELLOW + "\n[*] Applications with admin privileges:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("find /Applications -type f -perm +6000 -ls 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_keychain_dump():
    print(Fore.YELLOW + "\n[*] Keychain Access Check:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("security list-keychains")
    os.system("security list-smartcards")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_installed_tools():
    print(Fore.YELLOW + "\n[*] Development/Security Tools:")
    print("=" * 80)
    print(Style.RESET_ALL)
    tools = [
        "gcc", "g++", "python", "perl", "ruby", "curl", "wget", "nc", "nmap",
        "wireshark", "tcpdump", "gdb", "lldb", "ida_free", "hopper", "radare2"
    ]
    for tool in tools:
        os.system(f"which {tool} 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_logs():
    print(Fore.YELLOW + "\n[*] Log Files Permissions:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la /var/log/")
    os.system("ls -la /Library/Logs/")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_memory_protections():
    print(Fore.YELLOW + "\n[*] Memory Protections:")
    print("=" * 80)
    os.system("sysctl kern.protection")
    os.system("sysctl kern.nx")
    os.system("sysctl kern.aslr")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_debugging():
    print(Fore.YELLOW + "\n[*] Debugging Status:")
    print("=" * 80)
    os.system("csrutil status | grep 'debugging'")
    os.system("sysctl kern.development")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_unsigned_apps():
    print(Fore.YELLOW + "\n[*] Unsigned Applications:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("find /Applications -type f -name '*.app' -exec codesign -vv {} \\; 2>&1 | grep -v 'valid on disk'")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_saved_wifi():
    print(Fore.YELLOW + "\n[*] Saved WiFi Networks:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences RememberedNetworks")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_bash_history():
    print(Fore.YELLOW + "\n[*] Shell History Files:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la ~/.bash_history ~/.zsh_history 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_clipboard():
    print(Fore.YELLOW + "\n[*] Clipboard Content:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("pbpaste 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_safari_data():
    print(Fore.YELLOW + "\n[*] Safari Data:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la ~/Library/Safari/")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_mail_data():
    print(Fore.YELLOW + "\n[*] Mail Data:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la ~/Library/Mail/")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_vnc_config():
    print(Fore.YELLOW + "\n[*] VNC Configuration:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("defaults read /Library/Preferences/com.apple.VNCSettings.txt")
    os.system("lsof -i :5900")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_installed_frameworks():
    print(Fore.YELLOW + "\n[*] Installed Frameworks:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("ls -la /Library/Frameworks/")
    os.system("ls -la ~/Library/Frameworks/")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_system_integrity():
    print(Fore.YELLOW + "\n[*] System Integrity:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("spctl --status")
    os.system("csrutil status")
    os.system("nvram -p")
    print(Style.RESET_ALL)
    time.sleep(1)

def check_plaintext_passwords():
    print(Fore.YELLOW + "\n[*] Files Containing Potential Passwords:")
    print("=" * 80)
    print(Style.RESET_ALL)
    os.system("find / -type f -exec grep -l -i 'password' {} \\; 2>/dev/null")
    print(Style.RESET_ALL)
    time.sleep(1)

def print_result(result_type, message):
    if result_type == "success":
        print(f"{Fore.GREEN}[✓] {message}{Style.RESET_ALL}")
    elif result_type == "warning":
        print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
    elif result_type == "error":
        print(f"{Fore.RED}[✗] {message}{Style.RESET_ALL}")
    elif result_type == "info":
        print(f"{Fore.BLUE}[i] {message}{Style.RESET_ALL}")

def print_command_output(output):
    if output.strip():
        print(f"{Fore.WHITE}{output}{Style.RESET_ALL}")

def main():
    current_section = 0
    
    print_banner()
    
    # System Information Section
    current_section += 1
    print_section_header(current_section, "System Information")
    general_info()
    
    # Security Configuration Section
    current_section += 1
    print_section_header(current_section, "Security Configuration")
    check_sudo_access()
    check_sudo_config()
    
    # User Management Section
    current_section += 1
    print_section_header(current_section, "User Management")
    user_accounts()
    hidden_users()
    user_groups()
    
    # File Permissions Section
    current_section += 1
    print_section_header(current_section, "File Permissions")
    suid_binaries()
    sgid_binaries()
    
    # Network Security Section
    current_section += 1
    print_section_header(current_section, "Network Security")
    network_info()
    check_wifi()
    check_dns()
    
    # Application Security Section
    current_section += 1
    print_section_header(current_section, "Application Security")
    installed_software()
    check_unsigned_apps()
    check_quarantine()
    
    # System Security Section
    current_section += 1
    print_section_header(current_section, "System Security")
    check_filevault()
    check_system_integrity()
    check_memory_protections()
    
    # Final Summary
    print(f"\n{Fore.GREEN}{'═' * 80}")
    print(f"{Fore.GREEN}[✓] Security Scan Complete!")
    print(f"{Fore.GREEN}{'═' * 80}{Style.RESET_ALL}")
    
    # Print timestamp
    print(f"\n{Fore.BLUE}[i] Scan completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[✗] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


    
