#!/bin/bash
PID_FILE="/var/run/ocserv.pid"
conf_file="/etc/ocserv"
log_file="/tmp/ocserv.log"
check_pid(){
    if [[ ! -e ${PID_FILE} ]]; then
        PID=""
    else
        PID=$(cat ${PID_FILE})
    fi
}
[[ ! -z $PID ]] && kill -9 ${PID} && rm -f ${PID_FILE}
Del_iptables(){
    iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
    iptables -D INPUT -m state --state NEW -m udp -p udp --dport 80 -j ACCEPT
}
Save_iptables(){
    iptables-save > /etc/iptables.up.rules
}


update-rc.d -f ocserv remove
rm -rf /etc/init.d/ocserv
rm -rf "${conf_file}"
rm -rf "${log_file}"
cd '/usr/local/bin' && rm -f occtl
rm -f ocpasswd
cd '/usr/local/bin' && rm -f ocserv-fw
cd '/usr/local/sbin' && rm -f ocserv
cd '/usr/local/share/man/man8' && rm -f ocserv.8
rm -f ocpasswd.8
rm -f occtl.8

killall -9 ocserv-main

apt autoremove -y

echo && echo "ocserv uninstall completed ! " && echo


