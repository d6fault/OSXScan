# OSXScan 🔒

A comprehensive macOS security assessment and auditing tool that helps identify potential security vulnerabilities and misconfigurations in your system.

![OSXScan Banner](https://raw.githubusercontent.com/yourusername/OSXScan/main/banner.png)

## Versions Available 📦

### Python Version (Full Features)
- Rich colored output
- Progress tracking
- Detailed formatting
- Requires Python 3.7+ and colorama module

### Shell Script Version (Standalone)
- No dependencies required
- Works on any macOS system out of the box
- Runs directly in Terminal
- Basic output formatting
- Perfect for systems where Python isn't available

## Features 🛡️

- **System Information Analysis**
  - Hardware details
  - OS version
  - CPU information
  - System configuration

- **Security Configuration Checks**
  - SIP (System Integrity Protection) status
  - FileVault encryption status
  - Gatekeeper settings
  - XProtect status

- **User Management Audit**
  - User accounts enumeration
  - Hidden users detection
  - Group membership analysis
  - Wheel group access

- **Permission Analysis**
  - SUID/SGID binaries
  - World-writable files
  - Weak directory permissions
  - Service binary permissions

- **Network Security Assessment**
  - Network interfaces
  - Active connections
  - DNS configuration
  - WiFi settings

- **Application Security**
  - Installed software inventory
  - Unsigned applications
  - Quarantine database check
  - Admin privileged apps

- **System Security Checks**
  - Memory protections
  - Kernel extensions
  - Launch agents/daemons
  - Startup items

## Requirements 📋

### Python Version
- macOS 10.13 or later
- Python 3.7+
- Required Python packages:
  ```
  colorama>=0.4.6
  ```

### Shell Script Version
- macOS 10.13 or later
- Administrative privileges (for some checks)
- No additional dependencies required

## Installation 💻

### Python Version
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/OSXScan.git
   cd OSXScan
   ```

2. Install required packages:
   ```bash
   pip3 install -r requirements.txt
   ```

### Shell Script Version
1. Clone the repository or download the script:
   ```bash
   git clone https://github.com/yourusername/OSXScan.git
   cd OSXScan
   ```

2. Make the script executable:
   ```bash
   chmod +x OSXScan.sh
   ```

## Usage 🚀

### Python Version
Run with administrative privileges for full functionality:
```bash
sudo python3 OSXScan.py
```

### Shell Script Version
Run with administrative privileges for full functionality:
```bash
sudo ./OSXScan.sh
```

The tool will automatically:
1. Perform system security checks
2. Generate detailed reports for each section
3. Highlight potential security issues
4. Provide a completion summary

## Output Example 📝

```

                                                   *@@@@@                       
                                               @@@@@@@@@@                       
                                            (@@@@@@@@@@@@                       
                                          *@@@@@@@@@@@@@                        
                                         @@@@@@@@@@@@@,                         
                                        /@@@@@@@@@@@%                           
                                        @@@@@@@@@@                              
                                        ,@@@@,                                  
                    #@@@@@@@@@@@@@%,           #@@@@@@@@@@@@@@@@,               
                @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,           
             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         
           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         
          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.           
        (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                
       *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@             
        /@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           
         &@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       
          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      
           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@       
            *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@        
              @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.         
               (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&           
                 #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@             
                   &@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@               
                      @@@@@@@@@@@@@@@@*. ....,@@@@@@@@@@@@@@@@*                 
                         *@@@@@@                    @@@@@@/                     

           ╭─────────────────────────────────────────────────────────────────────╮
           │                          OSXScan v1.0                               │
           │                     Security Assessment Tool                        │
           │                                                                     │
           │              🔒 System Audit  |  🛡️ Vulnerability Scan              │
           │              👤 Access Review |  🚦 Security Policies               │
           ╰─────────────────────────────────────────────────────────────────────╯

════════════════════════════════════════════════════════════════════════════════


════════════════════════════════════════════════════════════════════════════════
[1] System Information
════════════════════════════════════════════════════════════════════════════════


[*] General Information:
================================================================================

ProductName:            macOS
ProductVersion:         15.3.1
BuildVersion:           24D70

Apple M4

uid=501(admin) gid=20(staff) groups=20(staff),101(access_bpf),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm),701(com.apple.sharepoint.group.1),33(_appstore),98(_lpadmin),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae)

admin

admins-Mac-mini.local

Darwin admins-Mac-mini.local 24.3.0 Darwin Kernel Version 24.3.0: Thu Jan  2 20:22:58 PST 2025; root:xnu-11215.81.4~3/RELEASE_ARM64_T8132 arm64

arm64

Mac16,10


```
