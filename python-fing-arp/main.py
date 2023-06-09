import socket
import nmap3
from macarna import mac_lookup
#from ssdpy import SSDPClient
import scapy.all as scapy
import upnpy
from netdisco.discovery import NetworkDiscovery
import subprocess
import os
from datetime import datetime
import configparser

#---Get own IP adresss for Networking-------------------

# get the hostname of the local machine
hostname = socket.gethostname()

# get the IP address of the local machine
ip_address = socket.gethostbyname(hostname)


target_ip = f"{ip_address}/24"
print(target_ip)

# create ARP request packet
arp = scapy.ARP(pdst=target_ip)
ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp

# send the packet and capture the response
# .srp-tuple: [0] - list ARP Packet sent & pos resp. [1] sent, no response
result = scapy.srp(packet, timeout=3, verbose=0)[0]
print(result)

# create a list of devices and their MAC addresses
'''
    pdst: the destination IP address of the ARP request or response packet
    psrc: the source IP address of the ARP request or response packet
    hwsrc: the MAC address of the device that sent the ARP request or response packet
'''
devices = []
for sent, received in result:
    devices.append({'ip': received.psrc, 'mac': received.hwsrc})

# print the list of devices
#https://stackoverflow.com/questions/50703738/what-is-the-meaning-of-the-scapy-arp-attributes

for device in devices:
    device_type = mac_lookup(device['mac'])
    print(f"IP: {device['ip']}, MAC: {device['mac']}, CORP: {device_type}")

print(f'--------Test-----NMAP3------')
nmap = nmap3.Nmap()
results = nmap.scan_top_ports(ip_address)
'''print(f'--------Test-----SSDPy------')
client = SSDPClient()
devices = client.m_search("ssdp:all")
for device in devices:
    print(device.get("usn"))'''

'''print(f'--------Test---SSDP with socket------')
# Define the SSDP multicast address and port
SSDP_IP = '239.255.255.250'
SSDP_PORT = 1900

# Define the SSDP discovery message
SSDP_DISCOVERY_MSG = (
    'M-SEARCH * HTTP/1.1\r\n'
    'Host: %s:%d\r\n'
    'Man: "ssdp:discover"\r\n'
    'ST: ssdp:all\r\n'
    'MX: 1\r\n\r\n'
) % (SSDP_IP, SSDP_PORT)

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.settimeout(5)

# Set the socket options for multicast
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

# Send the SSDP discovery message
sock.sendto(SSDP_DISCOVERY_MSG.encode(), (SSDP_IP, SSDP_PORT))

# Receive and process the SSDP responses
while True:
    try:
        data, addr = sock.recvfrom(1024)
        print('Received response from:', addr)
        print('Response:', data.decode())
        headers = data.decode().split('\r\n')
        for header in headers:
            if header.startswith('ST:'):
                device_type = header.split(': ')[1]
                print('Device Type:', device_type)
                break
        print('---')
    except socket.timeout:
        break

# Close the socket
sock.close()'''
#https://www.electricmonk.nl/log/2016/07/05/exploring-upnp-with-python/
print(f'--------Test-----UPNP------')
upnp = upnpy.UPnP()
devices = upnp.discover()
#device = devices[0]
#device_service= device.get_services()
print(devices)

print(f'--------Test-----NetDisco------')

netdis = NetworkDiscovery()
netdis.scan()

for dev in netdis.discover():
    print(dev)

netdis.stop()
#https://zerotomastery.io/cheatsheets/nmap-cheat-sheet/
print(f'--------Test-----NMAP3------')
def run_nmap_command(command):
    try:
        output = subprocess.check_output(command, shell=True, universal_newlines=True)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

#nmap_command = f'nmap -sV --script=broadcast-upnp-info -T4 {target_ip}'
#result = run_nmap_command(nmap_command)
print(result)


