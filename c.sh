#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
clear
ciscoportt=8080
echo -e "\nPlease input Cisco Port ."
printf "Default Port is \e[33m${ciscoportt}\e[0m, let it blank to use this Port: "
read defciscoport
if [[ -n "${defciscoport}" ]]; then
    ciscoportt=${defciscoport}
fi

sh_ver="1.0.5"
file="/usr/local/sbin/ocserv"
conf_file="/etc/ocserv"
conf="/etc/ocserv/ocserv.conf"
passwd_file="/etc/ocserv/ocpasswd"
log_file="/tmp/ocserv.log"
ocserv_ver="1.1.6"
PID_FILE="/var/run/ocserv.pid"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[INFO]${Font_color_suffix}"
Error="${Red_font_prefix}[ERROR]${Font_color_suffix}"
Tip="${Green_font_prefix}[WARN]${Font_color_suffix}"

check_root(){
    [[ $EUID != 0 ]] && echo -e "${Error} Current user is not root or don't have root access，can't continue，please switch to root or use command: ${Green_background_prefix}sudo su${Font_color_suffix} to get a temp root privilege(may request user password)." && exit 1
}

# Check system
check_sys(){
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    fi
    release="ubuntu"
    #bit=`uname -m`
}

check_installed_status(){
    [[ ! -e ${file} ]] && echo -e "${Error} ocserv haven't been installed, please check it!" && exit 1
    [[ ! -e ${conf} ]] && echo -e "${Error} ocserv config doesn't exist, please check it!" && [[ $1 != "un" ]] && exit 1
}

check_pid(){
    if [[ ! -e ${PID_FILE} ]]; then
        PID=""
    else
        PID=$(cat ${PID_FILE})
    fi
}

Get_ip(){
    ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
    if [[ -z "${ip}" ]]; then
        ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
        if [[ -z "${ip}" ]]; then
            ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
            if [[ -z "${ip}" ]]; then
                ip="VPS_IP"
            fi
        fi
    fi
}
Download_ocserv(){
    mkdir "ocserv" && cd "ocserv"
    wget "ftp://ftp.infradead.org/pub/ocserv/ocserv-${ocserv_ver}.tar.xz"
    [[ ! -s "ocserv-${ocserv_ver}.tar.xz" ]] && echo -e "${Error} ocserv source download failed!" && rm -rf "ocserv/" && rm -rf "ocserv-${ocserv_ver}.tar.xz" && exit 1
    tar -xJf ocserv-1.1.6.tar.xz && cd ocserv-1.1.6
    ./configure
    make
    make install
    cd .. && cd ..
    rm -rf ocserv/
    
    if [[ -e ${file} ]]; then
        mkdir "${conf_file}"
        wget --no-check-certificate -N -P "${conf_file}" "https://raw.githubusercontent.com/HamedAp/Ocserv-Ubuntu/main/ocserv.conf"
        [[ ! -s "${conf}" ]] && echo -e "${Error} ocserv config download failed!" && rm -rf "${conf_file}" && exit 1
    else
        echo -e "${Error} ocserv compiled failed!" && exit 1
    fi
}
Service_ocserv(){
    if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ocserv_debian -O /etc/init.d/ocserv; then
        echo -e "${Error} ocserv service management script downloadf failed!" && over
    fi
    chmod +x /etc/init.d/ocserv
    update-rc.d -f ocserv defaults
    echo -e "${Info} ocserv service management script download successfully."
}
rand(){
    min=10000
    max=$((60000-$min+1))
    num=$(date +%s%N)
    echo $(($num%$max+$min))
}
Generate_SSL(){
    lalala=$(rand)
    mkdir /tmp/ssl && cd /tmp/ssl
    echo -e 'cn = "'${lalala}'"
organization = "'${lalala}'"
serial = 1
expiration_days = 365
ca
signing_key
cert_signing_key
crl_signing_key' > ca.tmpl
    [[ $? != 0 ]] && echo -e "${Error} Write SSL cert signature template failed (ca.tmpl) !" && over
    certtool --generate-privkey --outfile ca-key.pem
    [[ $? != 0 ]] && echo -e "${Error} Generate SSL cert private key failed (ca-key.pem) !" && over
    certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem
    [[ $? != 0 ]] && echo -e "${Error} Generate SSL cert file failed (ca-cert.pem) !" && over
    
    Get_ip
    if [[ -z "$ip" ]]; then
        echo -e "${Error} get WAN IP failed !"
        read -e -p "Please manully input your WAN IP:" ip
        [[ -z "${ip}" ]] && echo "取消..." && over
    fi
    echo -e 'cn = "'${ip}'"
organization = "'${lalala}'"
expiration_days = 365
signing_key
encryption_key
tls_www_server' > server.tmpl
    [[ $? != 0 ]] && echo -e "${Error} Write SSL cert signature template failed (server.tmpl) !" && over
    certtool --generate-privkey --outfile server-key.pem
    [[ $? != 0 ]] && echo -e "${Error} Generate SSL cert private key failed (server-key.pem) !" && over
    certtool --generate-certificate --load-privkey server-key.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server.tmpl --outfile server-cert.pem
    [[ $? != 0 ]] && echo -e "${Error} Generate SSL cert file failed (server-cert.pem) !" && over
    
    mkdir /etc/ocserv/ssl
    mv ca-cert.pem /etc/ocserv/ssl/ca-cert.pem
    mv ca-key.pem /etc/ocserv/ssl/ca-key.pem
    mv server-cert.pem /etc/ocserv/ssl/server-cert.pem
    mv server-key.pem /etc/ocserv/ssl/server-key.pem
    cd .. && rm -rf /tmp/ssl/
}
Installation_dependency(){
    [[ ! -e "/dev/net/tun" ]] && echo -e "${Error} Your VPS haven't enabled TUN function, please contact your IDC, or use VPS control pannel to manully enable TUN/TAP !" && exit 1
    if [[ ${release} = "centos" ]]; then
        echo -e "${Error} CentOS is not offically supported, but you can edit my script !" && exit 1
    elif [[ ${release} = "debian" ]]; then
        cat /etc/issue |grep 9\..*>/dev/null
        if [[ $? = 0 ]]; then
            apt-get update
            apt-get install vim net-tools pkg-config build-essential libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin -y
        else
            mv /etc/apt/sources.list /etc/apt/sources.list.bak
            wget --no-check-certificate -O "/etc/apt/sources.list" "https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/sources/us.sources.list"
            apt-get update
            apt-get install vim net-tools pkg-config build-essential libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin -y
            rm -rf /etc/apt/sources.list
            mv /etc/apt/sources.list.bak /etc/apt/sources.list
            apt-get update
        fi
    else
        apt-get update
        apt-get install vim net-tools pkg-config build-essential libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin -y
    fi
}
Install_ocserv(){
    check_root
    [[ -e ${file} ]] && echo -e "${Error} ocserv is already installed !" && exit 1
    echo -e "${Info} Start to install/config dependencies..."
    Installation_dependency
    echo -e "${Info} Start to download/install config file..."
    Download_ocserv
    echo -e "${Info} Start to download/install service script(init)..."
    Service_ocserv
    echo -e "${Info} Start to self-sign SSL cert..."
    Generate_SSL
    echo -e "${Info} Start to set account settings..."
    Read_config
    Set_Config
    echo -e "${Info} Start to set iptables firewall ..."
    Set_iptables
    echo -e "${Info} Start to add iptables firewall rules..."
    Add_iptables
    echo -e "${Info} Start to save iptables firewall rules..."
    Save_iptables
    echo -e "${Info} All progress installed completed, now starting..."
    Start_ocserv
}
Start_ocserv(){
    check_installed_status
    check_pid
    [[ ! -z ${PID} ]] && echo -e "${Error} ocserv is running !" && exit 1
    /etc/init.d/ocserv start
    sleep 2s
    check_pid
    [[ ! -z ${PID} ]] && View_Config
}
Stop_ocserv(){
    check_installed_status
    check_pid
    [[ -z ${PID} ]] && echo -e "${Error} ocserv is NOT running !" && exit 1
    /etc/init.d/ocserv stop
}
Restart_ocserv(){
    check_installed_status
    check_pid
    [[ ! -z ${PID} ]] && /etc/init.d/ocserv stop
    /etc/init.d/ocserv start
    sleep 2s
    check_pid
    [[ ! -z ${PID} ]] && View_Config
}
Set_ocserv(){
    [[ ! -e ${conf} ]] && echo -e "${Error} ocserv config file doesn't exist !" && exit 1
    tcp_port=$(cat ${conf}|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
    udp_port=$(cat ${conf}|grep "udp-port ="|awk -F ' = ' '{print $NF}')
    vim ${conf}
    set_tcp_port=$(cat ${conf}|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
    set_udp_port=$(cat ${conf}|grep "udp-port ="|awk -F ' = ' '{print $NF}')
    Del_iptables
    Add_iptables
    Save_iptables
    echo "Restart ocserv ? (Y/n)"
    read -e -p "(Default: Y):" yn
    [[ -z ${yn} ]] && yn="y"
    if [[ ${yn} == [Yy] ]]; then
        Restart_ocserv
    fi
}

Set_tcp_port(){
    while true
    do
    
    [[ -z "$set_tcp_port" ]] && set_tcp_port=$ciscoportt
    echo $((${set_tcp_port}+0)) &>/dev/null
    if [[ $? -eq 0 ]]; then
        if [[ ${set_tcp_port} -ge 1 ]] && [[ ${set_tcp_port} -le 65535 ]]; then
            echo && echo -e "   TCP Port : ${Red_font_prefix}${set_tcp_port}${Font_color_suffix}" && echo
            break
        else
            echo -e "${Error} Please input a valid number！"
        fi
    else
        echo -e "${Error} Please input a valid number！"
    fi
    done
}
Set_udp_port(){
    while true
    do
    
    [[ -z "$set_udp_port" ]] && set_udp_port="${set_tcp_port}"
    echo $((${set_udp_port}+0)) &>/dev/null
    if [[ $? -eq 0 ]]; then
        if [[ ${set_udp_port} -ge 1 ]] && [[ ${set_udp_port} -le 65535 ]]; then
            echo && echo -e "   UDP Port : ${Red_font_prefix}${set_udp_port}${Font_color_suffix}" && echo
            break
        else
            echo -e "${Error} Please input a valid number！"
        fi
    else
        echo -e "${Error} Please input a valid number！"
    fi
    done
}
Set_Config(){
  
    Set_tcp_port
    Set_udp_port
    sed -i 's/tcp-port = '"$(echo ${tcp_port})"'/tcp-port = '"$(echo ${set_tcp_port})"'/g' ${conf}
    sed -i 's/udp-port = '"$(echo ${udp_port})"'/udp-port = '"$(echo ${set_udp_port})"'/g' ${conf}
}
Read_config(){
    [[ ! -e ${conf} ]] && echo -e "${Error} ocserv config file doesn't exist !" && exit 1
    conf_text=$(cat ${conf}|grep -v '#')
    tcp_port=$(echo -e "${conf_text}"|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
    udp_port=$(echo -e "${conf_text}"|grep "udp-port ="|awk -F ' = ' '{print $NF}')
    max_same_clients=$(echo -e "${conf_text}"|grep "max-same-clients ="|awk -F ' = ' '{print $NF}')
    max_clients=$(echo -e "${conf_text}"|grep "max-clients ="|awk -F ' = ' '{print $NF}')
}


View_Config(){
    Get_ip
    Read_config
    clear && echo "===================================================" && echo
    echo -e " AnyConnect Conf：" && echo
    
    echo -e "\n Link for clients : ${Green_font_prefix}${ip}:${tcp_port}${Font_color_suffix}"
    echo && echo "==================================================="
}

Add_iptables(){
    iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${set_tcp_port} -j ACCEPT
    iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${set_udp_port} -j ACCEPT
}

Save_iptables(){
    iptables-save > /etc/iptables.up.rules
}
Set_iptables(){
    echo -e "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
    ifconfig_status=$(ifconfig)
    if [[ -z ${ifconfig_status} ]]; then
        echo -e "${Error} ifconfig 未install !"
        read -e -p "Please input your interface name manully(eth0 ens3 enpXsX venet0):" Network_card
        [[ -z "${Network_card}" ]] && echo "Canceled..." && exit 1
    else
        Network_card=$(ifconfig|grep "eth0")
        if [[ ! -z ${Network_card} ]]; then
            Network_card="eth0"
        else
            Network_card=$(ifconfig|grep "ens3")
            if [[ ! -z ${Network_card} ]]; then
                Network_card="ens3"
            else
                Network_card=$(ifconfig|grep "venet0")
                if [[ ! -z ${Network_card} ]]; then
                    Network_card="venet0"
                else
                    ifconfig
                    read -e -p "Current network interface is not eth0 \ ens3(Debian9) \ venet0(OpenVZ) \ enpXsX(CentOS Ubuntu Latest), please manully input your NIC name:" Network_card
                    [[ -z "${Network_card}" ]] && echo "Canceled..." && exit 1
                fi
            fi
        fi
    fi
    iptables -t nat -A POSTROUTING -o ${Network_card} -j MASQUERADE
    
    iptables-save > /etc/iptables.up.rules
    echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules' > /etc/network/if-pre-up.d/iptables
    chmod +x /etc/network/if-pre-up.d/iptables
}

check_sys


Install_ocserv
touch /etc/ocserv/ocpasswd
