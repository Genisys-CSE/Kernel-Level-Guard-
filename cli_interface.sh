#!/bin/bash

# --- 1. SET WORKING DIRECTORY ---
cd "$(dirname "$0")"

# --- 2. CONFIGURATION: YOUR REAL PATHS ---
# Based on your previous screenshots
NET_MOD="./network/level_1.ko"
MITM_MOD="./network2/level_2.ko"
VIRUS_MOD="./sys_defence/file_def.ko"

# --- COLORS ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- CHECK ROOT ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root!${NC}" 
   echo "Try: sudo ./kguard_ui.sh"
   exit 1
fi

show_header() {
    clear
    echo -e "${GREEN}"
    echo "  _  __      _____ _    _    _    _____  ____  "
    echo " | |/ /     / ____| |  | |  / \  |  __ \|  _ \ "
    echo " | ' /_____| |  __| |  | | / _ \ | |__) | | | |"
    echo " |  <______| | |_ | |  | |/ ___ \|  _  /| |_| |"
    echo " | . \     | |__| | |__| / ____ \| | \ \|____/ "
    echo " |_|\_\     \_____|\____/_/    \_\_|  \_\____| "
    echo -e "${NC}"
    echo -e "${BLUE}      KERNEL DEFENSE SYSTEM v5.0 (Stable)      ${NC}"
    echo "------------------------------------------------"
}

check_status() {
    # 1. Check Network Module
    if lsmod | grep -q "level.1"; then
        NET_STATUS="${GREEN}[ACTIVE]${NC}"
    else
        NET_STATUS="${RED}[OFF]${NC}"
    fi

    # 2. Check MITM Module
    if lsmod | grep -q "level.2"; then
        MITM_STATUS="${GREEN}[ACTIVE]${NC}"
    else
        MITM_STATUS="${RED}[OFF]${NC}"
    fi

    # 3. Check Virus Module
    if lsmod | grep -q "file.def"; then
        VIRUS_STATUS="${GREEN}[ACTIVE]${NC}"
    else
        VIRUS_STATUS="${RED}[OFF]${NC}"
    fi
    
    echo -e " Firewall Guard:  $NET_STATUS"
    echo -e " MITM Guard:      $MITM_STATUS"
    echo -e " Syscall Shield:  $VIRUS_STATUS"
    echo "------------------------------------------------"
}

while true; do
    show_header
    check_status
    echo ""
    echo "  1) Load Network Security (Firewall + MITM)"
    echo "  2) Unload Network Security"
    echo ""
    echo "  3) Load Virus Protection (Syscall Shield)"
    echo "  4) Unload Virus Protection"
    echo ""
    echo "  5) View Recent Alerts (Last 10)"
    echo "  0) Exit"
    echo ""
    echo -n "Select an Option: "
    read choice

    case $choice in
        1)
            echo -e "\n${YELLOW}[*] Loading Network Modules...${NC}"
            
            if [ ! -f "$NET_MOD" ]; then
                echo -e "${RED}[!] File not found: $NET_MOD${NC}"
            else
                if insmod $NET_MOD; then
                    echo -e "${GREEN}[+] Firewall Loaded${NC}"
                else
                    echo -e "${RED}[!] Firewall Load Failed${NC}"
                fi
            fi

            if [ ! -f "$MITM_MOD" ]; then
                echo -e "${RED}[!] File not found: $MITM_MOD${NC}"
            else
                if insmod $MITM_MOD; then
                    echo -e "${GREEN}[+] MITM Guard Loaded${NC}"
                else
                    echo -e "${RED}[!] MITM Guard Load Failed${NC}"
                fi
            fi
            sleep 2
            ;;
        2)
            echo -e "\n${YELLOW}[*] Unloading Network Modules...${NC}"
            rmmod level_1 2>/dev/null || rmmod level-1
            rmmod level_2 2>/dev/null || rmmod level-2
            sleep 1
            ;;
        3)
            echo -e "\n${YELLOW}[*] Loading Virus Protection...${NC}"
            if [ ! -f "$VIRUS_MOD" ]; then
                echo -e "${RED}[!] File not found: $VIRUS_MOD${NC}"
            else
                if insmod $VIRUS_MOD; then
                    echo -e "${GREEN}[+] Syscall Shield Loaded${NC}"
                else
                    echo -e "${RED}[!] Shield Load Failed${NC}"
                fi
            fi
            sleep 2
            ;;
        4)
            echo -e "\n${YELLOW}[*] Unloading Virus Protection...${NC}"
            rmmod file_def 2>/dev/null || rmmod file-def
            sleep 1
            ;;
        5)
            echo -e "\n${YELLOW}[*] Fetching Last 10 Security Alerts...${NC}"
            echo "------------------------------------------------"
            # -T gives readable timestamps. We grep K-GUARD and take the last 10 lines.
            dmesg -T | grep --color=always "K-GUARD" | tail -n 10
            echo "------------------------------------------------"
            echo -e "${YELLOW}Press Enter to return to menu...${NC}"
            read temp
            ;;
        0)
            echo -e "\n${GREEN}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "\n${RED}Invalid Option!${NC}"
            sleep 1
            ;;
    esac
done
