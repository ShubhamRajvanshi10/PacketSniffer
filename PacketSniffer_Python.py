import socket
import os
import struct
import binascii

sock_created = False
sniffer_socket = 0

def analyze_udp_header(recv_data):
	udp_hdr  = struct.unpack("!4H" , recv_data[:8])
	src_port = udp_hdr[0]
	dst_port = udp_hdr[1]
	length   = udp_hdr[2]
	chk_sum  = udp_hdr[3]
	data     = recv_data[8:]
	
	print "|==============UDP HEADER ==============|"
	print "|\tSource:\t\t%hu" % src_port
	print "|\tDestination:\t\t%hu" % dst_port
	print "|\tLength:\t\t%hu" % length
	print "|\tcheckSum:\t\t%hu" % chk_sum
	
	return data

def analyze_tcp_header(recv_data):
	tcp_hdr  = struct.unpack("!2H2I4H" , recv_data[:20])
	src_port = tcp_hdr[0]             #first H
	dst_port = tcp_hdr[1]             #second H
	seq_num  = tcp_hdr[2]             #first I
	ack_num  = tcp_hdr[3]             #second I
	data_off = tcp_hdr[4] >> 12       #Third H
	reserved = tcp_hdr[4] >> 6        #Third H
	flags    = tcp_hdr[4] & 0x003f    #Third H
	win_size = tcp_hdr[5]             #Fourth H
	chk_sum  = tcp_hdr[6]
	urg_ptr  = tcp_hdr[7]
	data     = recv_data[20:]
	
	urg = bool(flags & 0x0020)
	ack = bool(flags & 0x0010)
	psh = bool(flags & 0x0008)
	rst = bool(flags & 0x0004)
	syn = bool(flags & 0x0002)
	fin = bool(flags & 0x0001)
	
	print "|==============TCP HEADER ==============|"
	print "|\tSource:\t\t%hu" % src_port
	print "|\tDestination:\t\t%hu" % dst_port
	print "|\tsequence num:\t\t%u" % seq_num
	print "|\tAcknowledge Num:\t\t%u" % ack_num
	#print "|\tData Offset:\t\t%hu" % data_off
	print "|\tFlags:"
	print "|\tURG:\t\t%d" % urg
	print "|\tACK:\t\t%d" % ack
	print "|\tPSH:\t\t%d" % psh
	print "|\tRST:\t\t%d" % rst
	print "|\tSYN:\t\t%d" % syn
	print "|\tFIN:\t\t%d" % fin
	print "|\tWindowSize:\t\t%hu" % win_size
	print "|\tCheckSUM:\t\t%hu" % chk_sum
	
	return data
	
def analyze_ip_header(recv_data):
	ip_hdr      = struct.unpack("!6H4s4s" , recv_data[:20])
	ver         = ip_hdr[0] >> 12    #only read first 4 bits
	hdr_len     = ip_hdr[0] & 0x0f00 #only read the last 4 bits
	ip_tos      = ip_hdr[0]          #first H
	tot_len     = ip_hdr[1]          #second H
	ip_id       = ip_hdr[2]          #third H
	no_frag     = ip_hdr[3] & 0x4000 #fourth H
	more_frag   = ip_hdr[3] & 0x2000 #fourth H
	offset      = ip_hdr[3] & 0x1fff #fourth H
	ttl         = ip_hdr[4] >> 8     #fifth H
	ip_proto    = ip_hdr[4] & 0x00ff #fifth H
	ip_chksum   = ip_hdr[5]          #sixth H
	src_ip = socket.inet_ntoa(ip_hdr[6]) #first 4s
	dst_ip = socket.inet_ntoa(ip_hdr[7]) #second 4s
	data = recv_data[20:]
	
	print "|==============IP HEADER ==============|"
	print "|\tVersion:\t%hu" % ver
	print "|\tIHL:\t%hu" % hdr_len
	print "|\tTypeOfService:\t%hu" % ip_tos
	print "|\tTotLen:\t%hu" % tot_len
	print "|\tip_id:\t%hu" % ip_id
	print "|\tno_frag:\t%hu" % no_frag
	print "|\tmore_frag:\t%hu" % more_frag
	print "|\toffset:\t%hu" % offset
	print "|\tTTL:\t%hu" % ttl
	print "|\tNext_proto:\t%hu" % ip_proto
	print "|\tChkSum:\t%hu" % ip_chksum
	print "|\tsrc_ip:\t%s" % src_ip
	print "|\tdst_ip:\t%s" % dst_ip
	
	if ip_proto == 6:
		tcp_upd = "TCP"
	elif ip_proto == 17:
		tcp_udp = "UDP"
	else:
		tcp_udp = "OTHERS"
	return data , tcp_udp
	
def analyse_ether_header(recv_data):
	eth_hdr = struct.unpack("!6s6sH" , recv_data[:14])
	dst_mac = binascii.hexlify(eth_hdr[0])
	src_mac = binascii.hexlify(eth_hdr[1])
	proto   = eth_hdr[2] >> 8
	data    = recv_data[14:]
	print "|==============ETHER HEADER ==============|"
	print "|\tDest:\t%s:%s:%s:%s:%s:%s" % (dst_mac[:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12])
	print "|\tSRC:\t%s:%s:%s:%s:%s:%s" % (src_mac[:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])
	print "|\tProto:\t%hu" %proto
	
	if proto == 0x08:
		return data, True
	return data, False
	
def main():
	global sock_created
	global sniffer_socket
	if sock_created == False:
		sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
		sock_created = True
		
	recv_data = sniffer_socket.recv(2048)
	
	os.system("clear")
	recv_data , ip_bool = analyse_ether_header(recv_data)
	if ip_bool:
		recv_data , tcp_udp = analyze_ip_header(recv_data)
		
	else:
		return
	
	if tcp_udp == 'TCP':
		recv_data = analyze_tcp_header(recv_data)
	elif tcp_udp == 'UDP':
		recv_data = analyze_udp_header(recv_data)
		
	return

while True:
	main()

