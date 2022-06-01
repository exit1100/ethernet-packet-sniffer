from sniffer import *

socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))

while True:
	packet, addr = socket.recvfrom(65535)
	dst_MAC, src_MAC, L3_Type = Get_Eth_Header(packet[:Packet_LEN_ETH])
	dst_MAC = Get_MAC_Addr(dst_MAC)
	src_MAC = Get_MAC_Addr(src_MAC)
	
	if L3_Type == IP_Type:
		Packet_LEN_L3 = 0
		Packet_LEN_L4 = 0
		IP_Header = Get_IP_Header(packet[14:])
		IP_Port = IP_Header[6]
		IP_Header_Length = (IP_Header[0]&15)*4
		IP_total_Length = IP_Header[2]
		src_IP = Get_IP_Addr(IP_Header[8])
		dst_IP = Get_IP_Addr(IP_Header[9])
		Packet_LEN_L3 = Packet_LEN_IP	
		src_Port = 0
		dst_Port = 0

		if protocols[IP_Port] == 'ICMP':
			ICMP_Header_Start = IP_Header_Length + Packet_LEN_ETH
			ICMP_Header = Get_ICMP_Header(packet[ICMP_Header_Start:])
			print('Layer 3: ICMP')
			print('ICMP Type:',ICMP_Header[0], '->', icmp_type[ICMP_Header[0]])
			print('Source MAC Address:', src_MAC)
			print('Destination MAC Address:',dst_MAC)
			print('Source IP Address:', src_IP)
			print('Destination IP Address:', dst_IP)
			Packet_LEN_L4 = Packet_LEN_ICMP
			Data_Start = Packet_LEN_ETH + IP_Header_Length + Packet_LEN_L4
			print('Data:',packet[Data_Start:])
			print()

		else:
			if protocols[IP_Port] == 'TCP':
				TCP_Header_Start = IP_Header_Length + Packet_LEN_ETH
				TCP_Header = Get_TCP_Header(packet[TCP_Header_Start:])
				src_Port = TCP_Header[0]
				dst_Port = TCP_Header[1]
				Packet_LEN_L4 = Packet_LEN_TCP

			elif protocols[IP_Port] == 'UDP':
				UDP_Header_Start = IP_Header_Length + Packet_LEN_ETH
				UDP_Header = Get_UDP_Header(packet[UDP_Header_Start:])
				src_Port = UDP_Header[0]
				dst_Port = UDP_Header[1]
				Packet_LEN_L4 = Packet_LEN_UDP

			print('Layer 3: IP')
			print('Source MAC Address:', src_MAC)
			print('Destination MAC Address:',dst_MAC)
			print('Source IP Address:', src_IP)
			print('Destination IP Address:', dst_IP)
			print('Layer 4:', protocols[IP_Port])

			if src_Port in protocols:
				print('Source IP Port:', protocols[src_Port], src_Port)
			else:
				print('Source IP Port: Undefined', src_Port)
			if dst_Port in protocols:
				print('Destination Port:', protocols[dst_Port], dst_Port)
			else:
				print('Destination Port: Undefined',  dst_Port)

			Data_Start = Packet_LEN_ETH + IP_Header_Length + Packet_LEN_L4			
			print('Data:',packet[Data_Start:])
			print()

	elif L3_Type == ARP_Type:
		ARP_Header = Get_ARP_Header(packet[Packet_LEN_ETH:])
		print('Layer 3: ARP')
		print('Operation:', ARP_Header[4], '->', arp_op[ARP_Header[4]])
		print('Source MAC Address:', Get_MAC_Addr(ARP_Header[5]))
		print('Source IP Address:', Get_IP_Addr(ARP_Header[6]))
		print('Target MAC Address:', Get_MAC_Addr(ARP_Header[7]))
		print('Target IP Address:', Get_IP_Addr(ARP_Header[8]))
		print()
		#Packet_LEN_L3 = Packet_LEN_ARP