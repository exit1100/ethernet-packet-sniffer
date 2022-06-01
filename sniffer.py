import socket
import struct

protocols = {1:'ICMP',6:'TCP',7:'ECHO',17:'UDP',20:'FTP',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',67:'DHCP',68:'DHCP',69:'TFTP',80:'HTTP',110:'POP3',143:'IMAP4',161:'SNMP',443:'HTTPS',520:'RIP'}
arp_op = {1:'ARP Request', 2:'ARP Reply', 3:'RARP Request', 4:'RARP Reply'}
icmp_type = {0:'Echo Reply', 3:'Destination Network Unreachable', 5:'Redirect', 8:'Echo Request',11:'TTL expired in trans'}
IP_Type = 0x0800
ARP_Type = 0x0806
Packet_LEN_ETH = 14
Packet_LEN_IP = 20
Packet_LEN_ARP = 28
Packet_LEN_TCP = 20
Packet_LEN_UDP = 8
Packet_LEN_ICMP = 4

def Get_MAC_Addr(input_MAC):
  	output_MAC = map('{:02X}'.format, input_MAC)
  	return ':'.join(output_MAC)

def Get_IP_Addr(input_IP):
  	output_IP = map('{:0d}'.format, input_IP)
  	return '.'.join(output_IP)

def Get_Eth_Header(packet):
	L3_Type = 'Undefined'
	dst_MAC, src_MAC, L3_Type = struct.unpack('! 6s 6s H',packet)
	return dst_MAC,src_MAC,L3_Type

def Get_IP_Header(packet):
	IP_Header = struct.unpack('!B B H H H B B H 4s 4s',packet[:Packet_LEN_IP])
	return IP_Header

def Get_TCP_Header(packet):
	TCP_Header = struct.unpack('!H H 2H 2H B B H H H',packet[:Packet_LEN_TCP])
	return TCP_Header

def Get_UDP_Header(packet):
	UDP_Header = struct.unpack('!H H H H',packet[:Packet_LEN_UDP])
	return UDP_Header

def Get_ARP_Header(packet):
	ARP_Header = struct.unpack('!H H B B H 6s 4s 6s 4s',packet[:Packet_LEN_ARP])	
	return ARP_Header

def Get_ICMP_Header(packet):
	ICMP_Header = struct.unpack('!B B H',packet[:Packet_LEN_ICMP])	
	return ICMP_Header
