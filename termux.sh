#!/bin/bash

# Colors
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
purple='\033[0;35m'
cyan='\033[0;36m'
rest='\033[0m'

# Check Dependencies build
check_dependencies_build() {
    local dependencies=("curl" "git" "golang")

    for dep in "${dependencies[@]}"; do
        if ! dpkg -s "${dep}" &> /dev/null; then
            echo -e "${yellow}${dep} is not installed. Installing...${rest}"
            pkg install "${dep}" -y
        fi
    done
}

# Check Dependencies
check_dependencies() {
    local dependencies=("curl" "wget" "unzip")

    for dep in "${dependencies[@]}"; do
        if ! dpkg -s "${dep}" &> /dev/null; then
            echo -e "${yellow}${dep} is not installed. Installing...${rest}"
            pkg install "${dep}" -y
        fi
    done
}

# Build
build() {
    if command -v warp &> /dev/null || command -v usef &> /dev/null; then
        echo -e "${green}Warp is already installed.${rest}"
        return
    fi

    echo -e "${green}Installing Warp...${rest}"
    pkg update -y && pkg upgrade -y
    check_dependencies_build

    if git clone https://github.com/uoosef/wireguard-go.git &&
        cd wireguard-go &&
        go build main.go &&
        chmod +x main &&
        cp main "$PREFIX/bin/usef" &&
        cp main "$PREFIX/bin/warp"; then
        echo -e "${green}Warp installed successfully.${rest}"
    else
        echo -e "${red}Error installing WireGuard VPN.${rest}"
    fi
}

# Install
install() {
    if command -v warp &> /dev/null || command -v usef &> /dev/null; then
        echo -e "${green}Warp is already installed.${rest}"
        return
    fi

    echo -e "${green}Installing Warp...${rest}"
    pkg update -y && pkg upgrade -y
    check_dependencies

    if wget https://github.com/uoosef/wireguard-go/releases/download/v0.0.2-alpha/warp-android-arm64.02bb9b.zip &&
        unzip warp-android-arm64.02bb9b.zip &&
        chmod +x warp &&
        cp warp "$PREFIX/bin/usef" &&
        cp warp "$PREFIX/bin/warp"; then
        rm "README.md" "LICENSE" "warp-android-arm64.02bb9b.zip"
        echo -e "${green}Warp installed successfully.${rest}"
    else
        echo -e "${red}Error installing Warp.${rest}"
    fi
}

# Get socks config
socks() {
   echo ""
   echo -e "${yellow}Copy this Config to ${purple}V2ray${green} Or ${purple}Nekobox ${yellow}and Exclude Termux${rest}"
   echo "================================================"
   echo -e "${green}socks://Og==@127.0.0.1:8086#warp_(usef)${rest}"
   echo "or"
   echo -e "${green}Manually create a SOCKS configuration with IP ${purple}127.0.0.1 ${green}and port${purple} 8086..${rest}"
   echo "================================================"
   echo -e "${yellow}To run again, type:${green} warp ${rest}or${green} usef ${rest}"
   echo "================================================"
   echo ""
}

#Uninstall
uninstall() {
    warp="$PREFIX/bin/warp"
    directory="/data/data/com.termux/files/home/wireguard-go"
    home="/data/data/com.termux/files/home"
    if [ -d "$warp" ]; then
        rm -rf "$directory" "$PREFIX/bin/usef" "$PREFIX/bin/warp" "$home/wgcf-profile.ini" "$home/wgcf-identity.json" > /dev/null 2>&1
        echo -e "${red}Uninstallation completed.${rest}"
    else
        echo -e "${yellow} ____________________________________${rest}"
        echo -e "${red} Not installed.Please Install First.${rest}${yellow}|"
        echo -e "${yellow} ____________________________________${rest}"
    fi
}

# Menu
menu() {
    clear
    echo -e "${green}By --> Peyman * Github.com/Ptechgithub * ${rest}"
    echo ""
    echo -e "${yellow}❤️Github.com/${cyan}uoosef${yellow}/wireguard-go❤️${rest}"
    echo -e "${purple}*********************************${rest}"
    echo -e "${blue}     ###${cyan} Warp in Termux ${blue}###${rest}   ${purple}  * ${rest}"
    echo -e "${purple}*********************************${rest}"
    echo -e "${cyan}1)${rest} ${green}Install Warp (vpn)${purple}           * ${rest}"
    echo -e "                              ${purple}  * ${rest}"
    echo -e "${cyan}2)${rest} ${green}Uninstall${rest}${purple}                    * ${rest}"
    echo -e "                              ${purple}  * ${rest}"
    echo -e "${cyan}3)${rest} ${green}Build (warp)${purple}                 * ${rest}"
    echo -e "                              ${purple}  * ${rest}"
    echo -e "${red}0)${rest} ${green}Exit                         ${purple}* ${rest}"
    echo -e "${purple}*********************************${rest}"
}

# Main
menu
read -p "Please enter your selection [0-3]:" choice

case "$choice" in
   1)
        install
        socks
        warp
        ;;
    2)
        uninstall
        ;;
    3)
        build
        ;;
    0)
        echo -e "${cyan}Exiting...${rest}"
        exit
        ;;
    *)
        echo "Invalid choice. Please select a valid option."
        ;;
esac