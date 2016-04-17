from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import arping


class ArpDefender:
    def __init__(self, parent):
        self.parent = parent
        self.requests = []
        self.responses = []
        self.arp_table = []


    def arp_pkt_callback(self, packet):
        if (not self.has_consistent_headers(packet)):
            return -1
        if (self.is_consistent_packet(packet)):
            self.update_arp_table(packet)
            return 1
        if (self.pass_active_check(packet)):
            self.update_arp_table(packet)
            return 1
        else:
            return 0

    def has_consistent_headers(self, packet):
        ether_src = packet[Ether].src
        ether_dst = packet[Ether].dst
        arp_src = packet[ARP].hwsrc
        arp_dst = packet[ARP].hwdst
        if packet[ARP].op == 2: # arp response
            return ether_src == arp_src # and ether_dst == arp_dst
        else: # arp request
            return ether_src == arp_src


    def is_consistent_packet(self, packet):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        for entry in self.arp_table:
            if entry['ip'] == ip:
                if entry['mac'] == mac:
                    return True
                else:
                    return False
        return True


    def pass_active_check(self, packet):
        ip = packet[ARP].psrc
        ans, unans = sr(IP(dst=ip) / TCP(dport=80, flags="S"), timeout=1)
        if not ans:
            return False
        return True


    def update_arp_table(self, packet):
        has_entry = False
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        for entry in self.arp_table:
            if entry['ip'] == ip:
                entry['mac'] = mac
                entry['received_at'] = time.time()
                has_entry = True
                break
        if not has_entry:
            entry = {'ip': ip, 'mac': mac, 'received_at': time.time()}
            self.arp_table.append(entry)
