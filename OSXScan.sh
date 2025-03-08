#!/bin/bash

# Color codes to match colorama
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

print_section_header() {
    local section_number=$1
    local title=$2
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════════════════════"
    echo -e "${YELLOW}[$section_number] $title"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}\n"
}

print_subsection() {
    local title=$1
    echo -e "\n${CYAN}[+] $title:${NC}"
    echo -e "${WHITE}----------------------------------------${NC}"
}

print_banner() {
    echo -e "${CYAN}                                                                                

                                                   *@@@@@                       
                                               @@@@@@@@@@                       
                                            (@@@@@@@@@@@@                       
                                          *@@@@@@@@@@@@@                        
                                         @@@@@@@@@@@@@,                         
                                        /@@@@@@@@@@@%                           
                                        @@@@@@@@@@                              
                                        ,@@@@,                                  
${BLUE}                    #@@@@@@@@@@@@@%,           #@@@@@@@@@@@@@@@@,               
                @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,           
             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         
${MAGENTA}           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         
          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.           
        (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              
${RED}        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
${YELLOW}       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
${GREEN}       *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@             
        /@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           
${CYAN}         &@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       
          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      
           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       
${BLUE}            *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        
              @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.         
               (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&           
${MAGENTA}                 #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@             
                   &@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
                      @@@@@@@@@@@@@@@@*. ....,@@@@@@@@@@@@@@@@*                 
                         *@@@@@@                    @@@@@@/                     ${NC}"
    
    echo -e "${WHITE}
           ╭─────────────────────────────────────────────────────────────────────╮
           │${CYAN}                          OSXScan v1.0                               ${WHITE}│
           │${YELLOW}                     Security Assessment Tool                        ${WHITE}│
           │                                                                     │
           │${GREEN}              🔒 System Audit  |  🛡️ Vulnerability Scan              ${WHITE}│
           │${CYAN}              👤 Access Review |  🚦 Security Policies               ${WHITE}│
           ╰─────────────────────────────────────────────────────────────────────╯${NC}"
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════════${NC}\n"
}

general_info() {
    echo -e "${YELLOW}\n[*] General Information:"
    echo "================================================================================${NC}"
    sw_vers
    sysctl -n machdep.cpu.brand_string
    id
    whoami
    hostname
    uname -a
    sysctl -n hw.machine
    sysctl -n hw.model
}

system_info() {
    echo -e "${YELLOW}\n[*] System Information:"
    echo "================================================================================${NC}"
    system_profiler
    sleep 1
}

check_sudo_access() {
    echo -e "${YELLOW}\n[*] Checking sudo access:"
    echo "================================================================================${NC}"
    sudo -n true
    sleep 1
}

sudo_version() {
    echo -e "${YELLOW}\n[*] Sudo Version:"
    echo "================================================================================${NC}"
    sudo -V
    sleep 1
}

suid_binaries() {
    echo -e "${YELLOW}\n[*] SUID Binaries:"
    echo "================================================================================${NC}"
    find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null
    sleep 1
}

sgid_binaries() {
    echo -e "${YELLOW}\n[*] SGID Binaries:"
    echo "================================================================================${NC}"
    find / -perm -2000 -type f -exec ls -l {} \; 2>/dev/null
    sleep 1
}

crontab_jobs() {
    echo -e "${YELLOW}\n[*] Cron Jobs:"
    echo "================================================================================${NC}"
    crontab -l
    sleep 1
}

weak_permissions() {
    echo -e "${YELLOW}\n[*] World-Writable Files:"
    echo "================================================================================${NC}"
    find / -perm -0002 -type f -exec ls -l {} \; 2>/dev/null
    sleep 1
}

login_items() {
    echo -e "${YELLOW}\n[*] System Login Items:"
    echo "================================================================================${NC}"
    echo -e "${CYAN}\n[+] LaunchAgents:${NC}"
    ls -la /Library/LaunchAgents
    echo -e "${CYAN}\n[+] LaunchDaemons:${NC}"
    ls -la /Library/LaunchDaemons
    
    echo -e "${YELLOW}\n[*] User Login Items:"
    echo "================================================================================${NC}"
    echo -e "${CYAN}\n[+] User LaunchAgents:${NC}"
    ls -la ~/Library/LaunchAgents
    echo -e "${CYAN}\n[+] System Events Login Items:${NC}"
    osascript -e 'tell application "System Events" to get the name of every login item'

    echo -e "${YELLOW}\n[*] Legacy Login Items:"
    echo "================================================================================${NC}"
    echo -e "${CYAN}\n[+] StartupItems:${NC}"
    ls -la /Library/StartupItems
    echo -e "${CYAN}\n[+] User LoginItems:${NC}"
    ls -la ~/Library/LoginItems
    sleep 1
}

user_accounts() {
    echo -e "${YELLOW}\n[*] User Accounts:"
    echo "================================================================================${NC}"
    dscl . list /Users | grep -v '^_'
    sleep 1
}

hidden_users() {
    echo -e "${YELLOW}\n[*] Hidden Users:"
    echo "================================================================================${NC}"
    dscl . list /Users | grep '^_'
    sleep 1
}

user_groups() {
    echo -e "${YELLOW}\n[*] User Groups:"
    echo "================================================================================${NC}"
    dscl . list /Groups | grep -v '^_'
    sleep 1
}

hidden_groups() {
    echo -e "${YELLOW}\n[*] Hidden Groups:"
    echo "================================================================================${NC}"
    dscl . list /Groups | grep '^_'
    sleep 1
}

wheel_group() {
    echo -e "${YELLOW}\n[*] Wheel Group Members:"
    echo "================================================================================${NC}"
    dseditgroup -o read wheel
    sleep 1
}

sip_status() {
    echo -e "${YELLOW}\n[*] SIP Status:"
    echo "================================================================================${NC}"
    csrutil status
    sleep 1
}

xprotect_status() {
    echo -e "${YELLOW}\n[*] XProtect Status:"
    echo "================================================================================${NC}"
    spctl status
    sleep 1
}

gatekeeper_status() {
    echo -e "${YELLOW}\n[*] Gatekeeper Status:"
    echo "================================================================================${NC}"
    spctl --status
    sleep 1
}

firewall_status() {
    echo -e "${YELLOW}\n[*] Firewall Status:"
    echo "================================================================================${NC}"
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
    sleep 1
}

ssh_keys() {
    echo -e "${YELLOW}\n[*] SSH Keys:"
    echo "================================================================================${NC}"
    ls -la ~/.ssh
    sleep 1
}

network_info() {
    echo -e "${YELLOW}\n[*] Network Information:"
    echo "================================================================================${NC}"
    ifconfig
    netstat -an | grep LISTEN
    lsof -i -P | grep LISTEN
    sleep 1
}

security_settings() {
    echo -e "${YELLOW}\n[*] Security Settings:"
    echo "================================================================================${NC}"
    defaults read /Library/Preferences/com.apple.security
    defaults read /Library/Preferences/com.apple.alf
    spctl --status
    csrutil status
    sleep 1
}

installed_software() {
    echo -e "${YELLOW}\n[*] Installed Software:"
    echo "================================================================================${NC}"
    ls -la /Applications
    pkgutil --pkgs
    brew list 2>/dev/null
    sleep 1
}

check_processes() {
    echo -e "${YELLOW}\n[*] Running Processes:"
    echo "================================================================================${NC}"
    ps aux
    launchctl list
    sleep 1
}

check_sharing() {
    echo -e "${YELLOW}\n[*] Sharing Settings:"
    echo "================================================================================${NC}"
    sharing -l
    systemsetup -getremotelogin
    systemsetup -getremoteappleevents
    sleep 1
}

check_bluetooth() {
    echo -e "${YELLOW}\n[*] Bluetooth Status:"
    echo "================================================================================${NC}"
    system_profiler SPBluetoothDataType
    sleep 1
}

check_wifi() {
    echo -e "${YELLOW}\n[*] WiFi Information:"
    echo "================================================================================${NC}"
    /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I
    networksetup -listallhardwareports
    sleep 1
}

check_dns() {
    echo -e "${YELLOW}\n[*] DNS Configuration:"
    echo "================================================================================${NC}"
    scutil --dns
    cat /etc/resolv.conf
    sleep 1
}

check_ssh() {
    echo -e "${YELLOW}\n[*] SSH Configuration:"
    echo "================================================================================${NC}"
    ls -la ~/.ssh/
    cat /etc/ssh/sshd_config 2>/dev/null
    sleep 1
}

check_certificates() {
    echo -e "${YELLOW}\n[*] System Certificates:"
    echo "================================================================================${NC}"
    security find-certificate -a -p /Library/Keychains/System.keychain
    sleep 1
}

check_tcc_permissions() {
    echo -e "${YELLOW}\n[*] TCC Permissions:"
    echo "================================================================================${NC}"
    sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db 'select * from access'
    sleep 1
}

check_kernel_extensions() {
    echo -e "${YELLOW}\n[*] Kernel Extensions:"
    echo "================================================================================${NC}"
    kextstat
    sleep 1
}

check_filevault() {
    echo -e "${YELLOW}\n[*] FileVault Status:"
    echo "================================================================================${NC}"
    fdesetup status
    diskutil apfs list
    sleep 1
}

check_mdm() {
    echo -e "${YELLOW}\n[*] MDM (Mobile Device Management) Status:"
    echo "================================================================================${NC}"
    profiles status -type enrollment
    profiles list
    sleep 1
}

check_time_machine() {
    echo -e "${YELLOW}\n[*] Time Machine Configuration:"
    echo "================================================================================${NC}"
    tmutil destinationinfo
    tmutil listbackups
    sleep 1
}

check_auto_updates() {
    echo -e "${YELLOW}\n[*] Software Update Settings:"
    echo "================================================================================${NC}"
    defaults read /Library/Preferences/com.apple.SoftwareUpdate
    softwareupdate --list
    sleep 1
}

check_password_policy() {
    echo -e "${YELLOW}\n[*] Password Policy Settings:"
    echo "================================================================================${NC}"
    pwpolicy -getaccountpolicies
    sleep 1
}

check_screen_sharing() {
    echo -e "${YELLOW}\n[*] Screen Sharing Status:"
    echo "================================================================================${NC}"
    launchctl list com.apple.screensharing
    lsof -i :5900
    sleep 1
}

check_icloud() {
    echo -e "${YELLOW}\n[*] iCloud Configuration:"
    echo "================================================================================${NC}"
    defaults read MobileMeAccounts
    sleep 1
}

check_startup_items() {
    echo -e "${YELLOW}\n[*] Additional Startup Items:"
    echo "================================================================================${NC}"
    echo -e "${CYAN}\n[+] Global Launch Daemons:${NC}"
    ls -la /System/Library/LaunchDaemons/
    echo -e "${CYAN}\n[+] User Login Items:${NC}"
    ls -la ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/
    sleep 1
}

check_quarantine() {
    echo -e "${YELLOW}\n[*] Quarantine Database:"
    echo "================================================================================${NC}"
    sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 'select * from LSQuarantineEvent'
    sleep 1
}

check_usb_devices() {
    echo -e "${YELLOW}\n[*] USB Device History:"
    echo "================================================================================${NC}"
    system_profiler SPUSBDataType
    sleep 1
}

check_recent_files() {
    echo -e "${YELLOW}\n[*] Recent Files:"
    echo "================================================================================${NC}"
    ls -la ~/Library/Recent\ Servers/
    ls -la ~/Library/Preferences/com.apple.recentitems.plist
    sleep 1
}

check_sudo_config() {
    echo -e "${YELLOW}\n[*] Sudo Configuration:"
    echo "================================================================================${NC}"
    sudo cat /etc/sudoers 2>/dev/null
    sudo cat /etc/sudoers.d/* 2>/dev/null
    sleep 1
}

check_env_paths() {
    echo -e "${YELLOW}\n[*] PATH Environment Variable:"
    echo "================================================================================${NC}"
    echo "$PATH"
    ls -la $(echo $PATH | tr ':' ' ')
    sleep 1
}

check_dyld() {
    echo -e "${YELLOW}\n[*] DYLD Environment:"
    echo "================================================================================${NC}"
    echo "$DYLD_LIBRARY_PATH"
    echo "$DYLD_INSERT_LIBRARIES"
    echo "$DYLD_FRAMEWORK_PATH"
    sleep 1
}

check_shell_configs() {
    echo -e "${YELLOW}\n[*] Shell Configuration Files:"
    echo "================================================================================${NC}"
    ls -la ~/.bash_profile ~/.bashrc ~/.zshrc ~/.zprofile /etc/profile /etc/bashrc 2>/dev/null
    sleep 1
}

check_special_permissions() {
    echo -e "${YELLOW}\n[*] Files with Special Permissions:"
    echo "================================================================================${NC}"
    echo -e "${CYAN}\n[+] Checking root-owned files with write access:${NC}"
    find / -uid 0 -perm -0002 -type f -ls 2>/dev/null
    echo -e "${CYAN}\n[+] Checking files with owner/group mismatch:${NC}"
    find / -type f -user root -perm -0002 ! -group root -ls 2>/dev/null
    sleep 1
}

check_cron_permissions() {
    echo -e "${YELLOW}\n[*] Cron Directory Permissions:"
    echo "================================================================================${NC}"
    ls -la /etc/cron* /etc/crontab /var/spool/cron/crontabs 2>/dev/null
    sleep 1
}

check_service_binaries() {
    echo -e "${YELLOW}\n[*] Service Binary Permissions:"
    echo "================================================================================${NC}"
    ls -la /Library/LaunchDaemons/* /System/Library/LaunchDaemons/* 2>/dev/null
    ls -la /Library/StartupItems/* /System/Library/StartupItems/* 2>/dev/null
    sleep 1
}

check_weak_apps() {
    echo -e "${YELLOW}\n[*] Applications with Weak Permissions:"
    echo "================================================================================${NC}"
    find /Applications -perm -2 -type f -ls 2>/dev/null
    find /Applications -perm -20 -type f -ls 2>/dev/null
    sleep 1
}

check_admin_applications() {
    echo -e "${YELLOW}\n[*] Applications with admin privileges:"
    echo "================================================================================${NC}"
    find /Applications -type f -perm +6000 -ls 2>/dev/null
    sleep 1
}

check_keychain_dump() {
    echo -e "${YELLOW}\n[*] Keychain Access Check:"
    echo "================================================================================${NC}"
    security list-keychains
    security list-smartcards
    sleep 1
}

check_installed_tools() {
    echo -e "${YELLOW}\n[*] Development/Security Tools:"
    echo "================================================================================${NC}"
    local tools=("gcc" "g++" "python" "perl" "ruby" "curl" "wget" "nc" "nmap" 
                "wireshark" "tcpdump" "gdb" "lldb" "ida_free" "hopper" "radare2")
    for tool in "${tools[@]}"; do
        which "$tool" 2>/dev/null
    done
    sleep 1
}

check_logs() {
    echo -e "${YELLOW}\n[*] Log Files Permissions:"
    echo "================================================================================${NC}"
    ls -la /var/log/
    ls -la /Library/Logs/
    sleep 1
}

check_memory_protections() {
    echo -e "${YELLOW}\n[*] Memory Protections:"
    echo "================================================================================${NC}"
    sysctl kern.protection
    sysctl kern.nx
    sysctl kern.aslr
    sleep 1
}

check_debugging() {
    echo -e "${YELLOW}\n[*] Debugging Status:"
    echo "================================================================================${NC}"
    csrutil status | grep 'debugging'
    sysctl kern.development
    sleep 1
}

check_unsigned_apps() {
    echo -e "${YELLOW}\n[*] Unsigned Applications:"
    echo "================================================================================${NC}"
    find /Applications -type f -name '*.app' -exec codesign -vv {} \; 2>&1 | grep -v 'valid on disk'
    sleep 1
}

check_saved_wifi() {
    echo -e "${YELLOW}\n[*] Saved WiFi Networks:"
    echo "================================================================================${NC}"
    defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences RememberedNetworks
    sleep 1
}

check_bash_history() {
    echo -e "${YELLOW}\n[*] Shell History Files:"
    echo "================================================================================${NC}"
    ls -la ~/.bash_history ~/.zsh_history 2>/dev/null
    sleep 1
}

check_clipboard() {
    echo -e "${YELLOW}\n[*] Clipboard Content:"
    echo "================================================================================${NC}"
    pbpaste 2>/dev/null
    sleep 1
}

check_safari_data() {
    echo -e "${YELLOW}\n[*] Safari Data:"
    echo "================================================================================${NC}"
    ls -la ~/Library/Safari/
    sleep 1
}

check_mail_data() {
    echo -e "${YELLOW}\n[*] Mail Data:"
    echo "================================================================================${NC}"
    ls -la ~/Library/Mail/
    sleep 1
}

check_vnc_config() {
    echo -e "${YELLOW}\n[*] VNC Configuration:"
    echo "================================================================================${NC}"
    defaults read /Library/Preferences/com.apple.VNCSettings.txt
    lsof -i :5900
    sleep 1
}

check_installed_frameworks() {
    echo -e "${YELLOW}\n[*] Installed Frameworks:"
    echo "================================================================================${NC}"
    ls -la /Library/Frameworks/
    ls -la ~/Library/Frameworks/
    sleep 1
}

check_system_integrity() {
    echo -e "${YELLOW}\n[*] System Integrity:"
    echo "================================================================================${NC}"
    spctl --status
    csrutil status
    nvram -p
    sleep 1
}

check_plaintext_passwords() {
    echo -e "${YELLOW}\n[*] Files Containing Potential Passwords:"
    echo "================================================================================${NC}"
    find / -type f -exec grep -l -i 'password' {} \; 2>/dev/null
    sleep 1
}

main() {
    local current_section=0
    
    print_banner
    
    # System Information Section
    ((current_section++))
    print_section_header "$current_section" "System Information"
    general_info
    
    # Security Configuration Section
    ((current_section++))
    print_section_header "$current_section" "Security Configuration"
    check_sudo_access
    check_sudo_config
    
    # User Management Section
    ((current_section++))
    print_section_header "$current_section" "User Management"
    user_accounts
    hidden_users
    user_groups
    
    # File Permissions Section
    ((current_section++))
    print_section_header "$current_section" "File Permissions"
    suid_binaries
    sgid_binaries
    weak_permissions
    
    # Network Security Section
    ((current_section++))
    print_section_header "$current_section" "Network Security"
    network_info
    check_wifi
    check_dns
    
    # Application Security Section
    ((current_section++))
    print_section_header "$current_section" "Application Security"
    installed_software
    check_unsigned_apps
    check_quarantine
    
    # System Security Section
    ((current_section++))
    print_section_header "$current_section" "System Security"
    check_filevault
    check_system_integrity
    check_memory_protections
    
    # Additional Checks
    check_mdm
    check_time_machine
    check_auto_updates
    check_password_policy
    check_screen_sharing
    check_icloud
    check_startup_items
    check_usb_devices
    check_recent_files
    check_installed_tools
    check_logs
    check_debugging
    check_saved_wifi
    check_bash_history
    check_clipboard
    check_safari_data
    check_mail_data
    check_vnc_config
    check_installed_frameworks
    check_plaintext_passwords
    
    # Final Summary
    echo -e "\n${GREEN}═════════════════════════════════════════════════════════════════"
    echo -e "${GREEN}[✓] Security Scan Complete!"
    echo -e "${GREEN}═════════════════════════════════════════════════════════════════${NC}"
    
    # Print timestamp
    echo -e "\n${BLUE}[i] Scan completed at: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
}

# Handle interrupts
trap 'echo -e "\n${RED}[!] Scan interrupted by user${NC}"; exit 1' INT

# Handle errors
trap 'echo -e "\n${RED}[✗] Error: $BASH_COMMAND failed${NC}"; exit 1' ERR

# Run main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi