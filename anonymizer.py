#!/usr/bin/env python3

"""
anonymize pcaps
run like ./anonymier.py [pcap file name]
"""

import sys
import os
os.sys.path.append('/opt/local/bin')
from scapy.all import *

"""
list of IPs we want to hide and list of IPs
we want to replace them with. The two lists
should obviously have the same size
(TODO: add ability to specify CIDRs)
"""

anon=['70.91.145.14','46.244.2.26','69.28.166.135']
replace=['192.0.2.1','203.0.113.1','192.0.2.2']


"""
anonymize an IPv4 IP address
"""
def anon4(ip):
  if ip[IP].src in anon:
    n=anon.index(ip[IP].src)
    ip[IP].src=replace[n]
  if ip[IP].dst in anon:
    n=anon.index(ip[IP].dst)
    ip[IP].dst=replace[n]    
  return ip   

"""
anonymize an IPv6 IP address
"""
def anon6(ip):
  if ip[IPv6].src in anon:
    n=anon.index(ip[IPv6].src)
    ip[IPv6].src=replace[n]
  if ip[IPv6].dst in anon:
    n=anon.index(ip[IPv6].dst)
    ip[IPv6].dst=replace[n]    
  return ip   


pkts=rdpcap(sys.argv[1])
for i in range(0,len(pkts)):
  if Ether in pkts[i]:
    # IPv4
    if pkts[i]['Ether'].type == 2048:
      pkts[i]['IP']=anon4(pkts[i]['IP'])
      p=pkts[i]['IP'].proto
      del pkts[i]['IP'].chksum
      if p == 17:
        del pkts[i]['UDP'].chksum
      if p == 6:
        del pkts[i]['TCP'].chksum
    # IPv6
    elif pkts[i]['Ether'].type == 34525:
      pkts[i]['IPv6']=anon6(pkts[i]['IPv6'])
      p=pkts[i]['IPv6'].nh
      if p == 17:
        del pkts[i]['UDP'].chksum
      if p == 6:
        del pkts[i]['TCP'].chksum
    # ARP
    elif pkts[i]['Ether'].type == 2054:
      s=pkts[i]['Ether'].src
    # VLAN
    elif pkts[i]['Ether'].type == 33024:
      s=pkts[i]['Ether'].src
    else:
      print("odd ethernet type: %s",(pkts[i]['Ether'].type,))
  else:
    pkts[i].summary()

wrpcap('out.pcap',pkts)


      
