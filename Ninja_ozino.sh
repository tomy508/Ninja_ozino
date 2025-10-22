#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

# Banner
echo -e "${GREEN}"
echo "========================================"
echo "    ADVANCED TERMUX SECURITY SUITE     "
echo "========================================"
echo -e "${NC}"

# Function to install required packages
install_packages() {
    echo -e "${YELLOW}[*] Installing required packages...${NC}"
    pkg update && pkg upgrade -y
    pkg install -y python php curl wget git nmap figlet toilet ruby -y
    pip install requests mechanize bs4 scapy
    gem install lolcat
    echo -e "${GREEN}[+] Packages installed successfully!${NC}"
}

# 1. Phishing Tool
phishing_tool() {
    echo -e "${CYAN}[1] Phishing Attack Tool${NC}"
    echo -e "${YELLOW}This tool creates phishing pages for educational purposes${NC}"
    
    read -p "Enter phishing type (facebook/instagram/gmail): " phish_type
    read -p "Enter port to use (default 8080): " port
    port=${port:-8080}
    
    case $phish_type in
        facebook|fb)
            git clone https://github.com/htr-tech/zphisher.git
            cd zphisher
            bash zphisher.sh
            ;;
        instagram|ig)
            git clone https://github.com/thelinuxchoice/shellphish.git
            cd shellphish
            bash shellphish.sh
            ;;
        gmail|google)
            git clone https://github.com/htr-tech/nexphisher.git
            cd nexphisher
            bash nexphisher.sh
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
}

# 2. IP Information
ip_info() {
    echo -e "${CYAN}[2] IP Information Tool${NC}"
    
    read -p "Enter IP address (or press enter for your IP): " ip
    if [ -z "$ip" ]; then
        ip=$(curl -s ifconfig.me)
    fi
    
    echo -e "${YELLOW}Gathering information for IP: $ip${NC}"
    
    # Using ipapi.co
    curl -s "http://ipapi.co/$ip/json/" | python -m json.tool
    
    # Additional info
    echo -e "\n${GREEN}Additional Information:${NC}"
    whois $ip | grep -E "country|org-name|netname|descr"
}

# 3. Location Tracking
location_tracking() {
    echo -e "${CYAN}[3] Location Tracking Tool${NC}"
    
    read -p "Enter IP address: " ip
    read -p "Enter phone number (with country code): " phone
    
    echo -e "${YELLOW}[*] Tracking location...${NC}"
    
    # IP based tracking
    if [ ! -z "$ip" ]; then
        echo -e "${BLUE}IP Location:${NC}"
        curl -s "https://ipinfo.io/$ip" | python -m json.tool
    fi
    
    # Phone number tracking (basic)
    if [ ! -z "$phone" ]; then
        echo -e "${BLUE}Phone Number Info:${NC}"
        curl -s "http://apilayer.net/api/validate?access_key=demo&number=$phone" | python -m json.tool
    fi
}

# 4. Android Phone Security Scanner
android_hack_tool() {
    echo -e "${CYAN}[4] Android Security Scanner${NC}"
    echo -e "${YELLOW}This tool scans for security vulnerabilities${NC}"
    
    echo -e "${RED}WARNING: This is for educational purposes only!${NC}"
    
    # Check device vulnerabilities
    echo -e "${BLUE}[*] Scanning device...${NC}"
    
    # Check if device is rooted
    if [ -f "/system/xbin/su" ] || [ -f "/system/bin/su" ]; then
        echo -e "${RED}[!] Device is rooted${NC}"
    else
        echo -e "${GREEN}[+] Device is not rooted${NC}"
    fi
    
    # Check ADB status
    adb_status=$(getprop service.adb.tcp.port)
    if [ ! -z "$adb_status" ]; then
        echo -e "${RED}[!] ADB debugging enabled${NC}"
    else
        echo -e "${GREEN}[+] ADB debugging disabled${NC}"
    fi
    
    # Check installed apps security
    echo -e "${BLUE}[*] Analyzing installed apps...${NC}"
    pm list packages | head -20
}

# 5. OTP Hacking Tool (Educational)
otp_hack_tool() {
    echo -e "${CYAN}[5] OTP Security Research Tool${NC}"
    echo -e "${YELLOW}This demonstrates OTP vulnerabilities${NC}"
    
    echo -e "${RED}WARNING: For educational purposes only!${NC}"
    
    # Simulate OTP brute force (educational)
    read -p "Enter target phone number: " phone
    
    echo -e "${BLUE}[*] Demonstrating OTP vulnerabilities...${NC}"
    echo -e "${YELLOW}Common OTP vulnerabilities:${NC}"
    echo "1. Weak OTP patterns"
    echo "2. SIM swapping"
    echo "3. Social engineering"
    echo "4. Man-in-the-middle attacks"
    
    # Generate sample OTP patterns
    echo -e "\n${GREEN}Sample OTP Patterns:${NC}"
    for i in {1..5}; do
        echo "OTP $i: $((RANDOM % 9000 + 1000))"
    done
}

# 6. Camera Security Test
camera_hack_tool() {
    echo -e "${CYAN}[6] Camera Security Scanner${NC}"
    
    echo -e "${YELLOW}Checking camera permissions and access...${NC}"
    
    # Check if termux-camera is available
    if command -v termux-camera-info &> /dev/null; then
        echo -e "${GREEN}[+] Termux camera access available${NC}"
        termux-camera-info
    else
        echo -e "${RED}[-] Termux camera not available${NC}"
    fi
    
    # Camera security tips
    echo -e "\n${BLUE}Camera Security Tips:${NC}"
    echo "1. Cover camera when not in use"
    echo "2. Review app permissions"
    echo "3. Keep system updated"
    echo "4. Use camera indicator apps"
}

# 7. DDoS Attack Tool (Educational)
ddos_tool() {
    echo -e "${CYAN}[7] DDoS Educational Tool${NC}"
    echo -e "${RED}WARNING: Only for educational and authorized testing!${NC}"
    
    read -p "Enter target URL/IP: " target
    read -p "Enter port (default 80): " port
    read -p "Enter duration in seconds: " duration
    
    port=${port:-80}
    
    echo -e "${YELLOW}[*] Starting educational DDoS simulation...${NC}"
    echo -e "${BLUE}Target: $target${NC}"
    echo -e "${BLUE}Port: $port${NC}"
    echo -e "${BLUE}Duration: ${duration}s${NC}"
    
    # Simple ping flood (educational)
    timeout $duration ping -f $target | while read line; do
        echo -e "${RED}$line${NC}"
    done
    
    echo -e "${GREEN}[+] DDoS simulation completed${NC}"
}

# 8. Termux Banner Change
termux_banner_change() {
    echo -e "${CYAN}[8] Termux Banner Customization${NC}"
    
    echo -e "${YELLOW}Customizing Termux banner...${NC}"
    
    # Backup original motd
    cp $PREFIX/etc/motd $PREFIX/etc/motd.backup 2>/dev/null
    
    # Create custom banner
    cat > $PREFIX/etc/motd << EOF
================================
    WELCOME TO TERMUX PRO
    Security Research Lab
================================
EOF

    echo -e "${GREEN}[+] Banner changed successfully!${NC}"
    echo -e "${YELLOW}Restart Termux to see changes${NC}"
}

# 9. Termux Text and Color Change
termux_style_change() {
    echo -e "${CYAN}[9] Termux Style Customization${NC}"
    
    echo -e "${YELLOW}Available options:${NC}"
    echo "1. Change font"
    echo "2. Change color scheme"
    echo "3. Change cursor style"
    echo "4. Reset to default"
    
    read -p "Choose option: " style_choice
    
    case $style_choice in
        1)
            echo -e "${BLUE}Installing fonts...${NC}"
            git clone https://github.com/termux/termux-styling
            echo -e "${GREEN}Use Termux:Styling app to change fonts${NC}"
            ;;
        2)
            echo -e "${BLUE}Available color schemes:${NC}"
            echo "1. Dark (default)"
            echo "2. Light"
            echo "3. Red"
            echo "4. Green"
            echo "5. Blue"
            ;;
        3)
            echo -e "${BLUE}Changing cursor...${NC}"
            # Change cursor via properties
            setprop ro.termux.cursor.style block
            ;;
        4)
            # Reset to default
            rm -f $PREFIX/etc/motd
            setprop ro.termux.cursor.style line
            echo -e "${GREEN}[+] Style reset to default${NC}"
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
}

# 10. Voice Hack Tool
voice_hack_tool() {
    echo -e "${CYAN}[10] Voice Security Tool${NC}"
    
    echo -e "${YELLOW}Voice security testing tools...${NC}"
    
    # Check TTS capabilities
    if command -v termux-tts-speak &> /dev/null; then
        echo -e "${GREEN}[+] Text-to-Speech available${NC}"
        
        read -p "Enter text to speak: " text
        termux-tts-speak "$text"
        
        # TTS settings
        echo -e "${BLUE}TTS Engines:${NC}"
        termux-tts-engines
    else
        echo -e "${RED}[-] TTS not available${NC}"
    fi
    
    # Voice recording test
    echo -e "\n${BLUE}Voice Recording Test:${NC}"
    if command -v termux-microphone-record &> /dev/null; then
        echo -e "${GREEN}[+] Microphone access available${NC}"
        read -p "Record audio? (y/n): " record
        if [ "$record" == "y" ]; then
            termux-microphone-record -d 5 -f recording.wav
            echo -e "${GREEN}[+] Recording saved${NC}"
        fi
    fi
}

# 11. Phone Call Tools
call_hack_tool() {
    echo -e "${CYAN}[11] Call Security Tools${NC}"
    
    echo -e "${YELLOW}Call-related security testing...${NC}"
    
    # Check call permissions
    if command -v termux-telephony-call &> /dev/null; then
        echo -e "${GREEN}[+] Call permissions available${NC}"
        
        echo -e "${BLUE}Options:${NC}"
        echo "1. Make test call"
        echo "2. Check call history"
        echo "3. Get device info"
        
        read -p "Choose option: " call_choice
        
        case $call_choice in
            1)
                read -p "Enter phone number: " number
                termux-telephony-call $number
                ;;
            2)
                termux-telephony-cellinfo
                ;;
            3)
                termux-telephony-deviceinfo
                ;;
            *)
                echo -e "${RED}Invalid option!${NC}"
                ;;
        esac
    else
        echo -e "${RED}[-] Call permissions not available${NC}"
    fi
}

# 12. Contact Security Scanner
contact_hack_tool() {
    echo -e "${CYAN}[12] Contact Security Scanner${NC}"
    
    echo -e "${YELLOW}Analyzing contact security...${NC}"
    
    if command -v termux-contact-list &> /dev/null; then
        echo -e "${GREEN}[+] Contact access available${NC}"
        
        # List contacts (first 10 for privacy)
        echo -e "${BLUE}First 10 contacts:${NC}"
        termux-contact-list | head -n 10 | python -m json.tool
        
        # Contact security tips
        echo -e "\n${GREEN}Contact Security Tips:${NC}"
        echo "1. Encrypt contact backups"
        echo "2. Use contact verification"
        echo "3. Be careful with contact sharing apps"
        echo "4. Regularly review contact permissions"
    else
        echo -e "${RED}[-] Contact access not available${NC}"
    fi
}

# 13. SMS Bombing Tool (Educational)
sms_bombing_tool() {
    echo -e "${CYAN}[13] SMS Security Testing Tool${NC}"
    echo -e "${RED}WARNING: For educational purposes only!${NC}"
    echo -e "${RED}Use only on your own numbers with permission!${NC}"
    
    read -p "Enter target phone number: " number
    read -p "Enter number of messages (1-10): " count
    read -p "Enter message: " message
    
    # Validate count
    if [ $count -gt 10 ]; then
        echo -e "${RED}Maximum 10 messages allowed for testing!${NC}"
        count=10
    fi
    
    echo -e "${YELLOW}[*] Sending test messages...${NC}"
    
    for ((i=1; i<=$count; i++)); do
        echo -e "${BLUE}Message $i: $message${NC}"
        # Actual SMS sending would require SMS permissions
        # termux-sms-send -n "$number" "$message $i"
        sleep 1
    done
    
    echo -e "${GREEN}[+] Test completed${NC}"
    echo -e "${YELLOW}Note: Actual SMS sending requires proper permissions${NC}"
}

# 14. Network Scanner
network_scanner() {
    echo -e "${CYAN}[14] Network Scanner${NC}"
    
    echo -e "${YELLOW}Scanning network...${NC}"
    
    # Get local IP
    local_ip=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')
    echo -e "${BLUE}Local IP: $local_ip${NC}"
    
    # Scan local network
    read -p "Enter network to scan (e.g., 192.168.1.0/24): " network
    if [ -z "$network" ]; then
        network="${local_ip%.*}.0/24"
    fi
    
    nmap -sn $network | while read line; do
        if [[ $line == *"Nmap scan report"* ]]; then
            echo -e "${GREEN}$line${NC}"
        elif [[ $line == *"MAC Address"* ]]; then
            echo -e "${YELLOW}$line${NC}"
        fi
    done
}

# 15. WiFi Security Scanner
wifi_scanner() {
    echo -e "${CYAN}[15] WiFi Security Scanner${NC}"
    
    echo -e "${YELLOW}Scanning WiFi networks...${NC}"
    
    termux-wifi-scaninfo | while read line; do
        echo -e "${BLUE}$line${NC}"
    done
    
    # WiFi security info
    echo -e "\n${GREEN}WiFi Security Tips:${NC}"
    echo "1. Use WPA3 encryption"
    echo "2. Change default router password"
    echo "3. Disable WPS"
    echo "4. Use strong WiFi password"
    echo "5. Enable MAC filtering"
}

# 16. Password Strength Checker
password_checker() {
    echo -e "${CYAN}[16] Password Strength Checker${NC}"
    
    read -p "Enter password to check: " password
    
    strength=0
    
    # Length check
    if [ ${#password} -ge 8 ]; then
        ((strength++))
        echo -e "${GREEN}[+] Good length${NC}"
    else
        echo -e "${RED}[-] Too short${NC}"
    fi
    
    # Upper/lower case check
    if [[ "$password" =~ [A-Z] ]] && [[ "$password" =~ [a-z] ]]; then
        ((strength++))
        echo -e "${GREEN}[+] Mixed case${NC}"
    else
        echo -e "${RED}[-] Needs mixed case${NC}"
    fi
    
    # Number check
    if [[ "$password" =~ [0-9] ]]; then
        ((strength++))
        echo -e "${GREEN}[+] Contains numbers${NC}"
    else
        echo -e "${RED}[-] Needs numbers${NC}"
    fi
    
    # Special char check
    if [[ "$password" =~ [!@#$%^&*] ]]; then
        ((strength++))
        echo -e "${GREEN}[+] Contains special characters${NC}"
    else
        echo -e "${RED}[-] Needs special characters${NC}"
    fi
    
    # Final assessment
    echo -e "\n${BLUE}Password Strength: $strength/4${NC}"
    if [ $strength -eq 4 ]; then
        echo -e "${GREEN}Strong password!${NC}"
    elif [ $strength -ge 2 ]; then
        echo -e "${YELLOW}Medium strength password${NC}"
    else
        echo -e "${RED}Weak password!${NC}"
    fi
}

# 17. Encryption Tool
encryption_tool() {
    echo -e "${CYAN}[17] File Encryption Tool${NC}"
    
    echo -e "${YELLOW}File encryption/decryption${NC}"
    
    echo "1. Encrypt file"
    echo "2. Decrypt file"
    read -p "Choose option: " enc_choice
    
    case $enc_choice in
        1)
            read -p "Enter file to encrypt: " file
            read -p "Enter password: " password
            openssl enc -aes-256-cbc -salt -in "$file" -out "$file.enc" -k "$password"
            echo -e "${GREEN}[+] File encrypted: $file.enc${NC}"
            ;;
        2)
            read -p "Enter file to decrypt: " file
            read -p "Enter password: " password
            openssl enc -aes-256-cbc -d -in "$file" -out "${file%.enc}" -k "$password"
            echo -e "${GREEN}[+] File decrypted: ${file%.enc}${NC}"
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
}

# 18. Social Engineering Toolkit
social_engineering_tool() {
    echo -e "${CYAN}[18] Social Engineering Toolkit${NC}"
    echo -e "${RED}For educational purposes only!${NC}"
    
    echo -e "${YELLOW}Common social engineering techniques:${NC}"
    echo "1. Phishing awareness"
    echo "2. Pretexting examples"
    echo "3. Baiting scenarios"
    echo "4. Quid pro quo examples"
    
    read -p "Choose technique to learn: " se_choice
    
    case $se_choice in
        1)
            echo -e "${BLUE}Phishing Awareness:${NC}"
            echo "- Check email sender addresses"
            echo "- Don't click suspicious links"
            echo "- Verify through official channels"
            echo "- Use two-factor authentication"
            ;;
        2)
            echo -e "${BLUE}Pretexting Examples:${NC}"
            echo "- Fake IT support calls"
            echo "- Impersonating officials"
            echo "- Fake emergency scenarios"
            ;;
        3)
            echo -e "${BLUE}Baiting Scenarios:${NC}"
            echo "- Infected USB drops"
            echo "- Fake software downloads"
            echo "- Malicious advertisements"
            ;;
        4)
            echo -e "${BLUE}Quid Pro Quo:${NC}"
            echo "- Fake tech support"
            echo "- Fake free offers"
            echo "- Fake job opportunities"
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
}

# 19. Digital Forensics Tool
forensics_tool() {
    echo -e "${CYAN}[19] Digital Forensics Tool${NC}"
    
    echo -e "${YELLOW}Basic digital forensics commands...${NC}"
    
    echo "1. Check file metadata"
    echo "2. Analyze network connections"
    echo "3. Check running processes"
    echo "4. Analyze system logs"
    
    read -p "Choose option: " forensics_choice
    
    case $forensics_choice in
        1)
            read -p "Enter filename: " file
            if command -v exiftool &> /dev/null; then
                exiftool "$file"
            else
                file "$file"
                stat "$file"
            fi
            ;;
        2)
            netstat -tulpn 2>/dev/null || ss -tulpn
            ;;
        3)
            ps aux | head -20
            ;;
        4)
            logcat | head -50
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
}

# 20. Vulnerability Scanner
vulnerability_scanner() {
    echo -e "${CYAN}[20] Vulnerability Scanner${NC}"
    
    echo -e "${YELLOW}Scanning for common vulnerabilities...${NC}"
    
    # Check for outdated packages
    pkg list-upgradable
    
    # Check file permissions
    echo -e "\n${BLUE}Checking sensitive file permissions...${NC}"
    ls -la /data/data/com.termux/files/usr/etc/ | head -10
    
    # Check for known vulnerabilities
    echo -e "\n${BLUE}Security Recommendations:${NC}"
    echo "1. Keep Termux updated"
    echo "2. Use strong passwords"
    echo "3. Encrypt sensitive files"
    echo "4. Be careful with permissions"
    echo "5. Use VPN for sensitive work"
}

# Main Menu
main_menu() {
    while true; do
        clear
        echo -e "${GREEN}"
        echo "========================================"
        echo "    ADVANCED TERMUX SECURITY SUITE     "
        echo "========================================"
        echo -e "${NC}"
        
        echo -e "${CYAN}Available Tools:${NC}"
        echo "1. Phishing Tool (Educational)"
        echo "2. IP Information"
        echo "3. Location Tracking"
        echo "4. Android Security Scanner"
        echo "5. OTP Security Research"
        echo "6. Camera Security Test"
        echo "7. DDoS Educational Tool"
        echo "8. Termux Banner Change"
        echo "9. Termux Style Customization"
        echo "10. Voice Security Tool"
        echo "11. Call Security Tools"
        echo "12. Contact Security Scanner"
        echo "13. SMS Security Testing"
        echo "14. Network Scanner"
        echo "15. WiFi Security Scanner"
        echo "16. Password Strength Checker"
        echo "17. File Encryption Tool"
        echo "18. Social Engineering Toolkit"
        echo "19. Digital Forensics Tool"
        echo "20. Vulnerability Scanner"
        echo "21. Install Required Packages"
        echo "22. Exit"
        
        echo -e "\n${YELLOW}Select an option (1-22): ${NC}"
        read choice
        
        case $choice in
            1) phishing_tool ;;
            2) ip_info ;;
            3) location_tracking ;;
            4) android_hack_tool ;;
            5) otp_hack_tool ;;
            6) camera_hack_tool ;;
            7) ddos_tool ;;
            8) termux_banner_change ;;
            9) termux_style_change ;;
            10) voice_hack_tool ;;
            11) call_hack_tool ;;
            12) contact_hack_tool ;;
            13) sms_bombing_tool ;;
            14) network_scanner ;;
            15) wifi_scanner ;;
            16) password_checker ;;
            17) encryption_tool ;;
            18) social_engineering_tool ;;
            19) forensics_tool ;;
            20) vulnerability_scanner ;;
            21) install_packages ;;
            22)
                echo -e "${GREEN}Thanks for using the security suite!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option! Please try again.${NC}"
                ;;
        esac
        
        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read
    done
}

# Check if running in Termux
if [ ! -d "/data/data/com.termux/files/usr" ]; then
    echo -e "${RED}This script is designed for Termux!${NC}"
    exit 1
fi

# Start the main menu
main_menu