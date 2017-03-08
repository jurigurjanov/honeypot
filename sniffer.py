#!/bin/python
# Packet sniffer in python
# For Linux - Sniffs all incoming and outgoing packets :)
# Silver Moon (m00n.silv3r@gmail.com)

import socket, sys
from struct import *

loc_mac = "00:15:17:ac:55:6c"
d_mac = "ff:ff:ff:ff:ff:ff"
d_mac1 = "00:00:00:00:00:00"
sniff_out = 'sniff_data.txt'

f = open(sniff_out,'a+')
# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


# create a AF_PACKET type raw socket (thats basically packet level)
# define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error, msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# receive a packet
while True:
    packet = s.recvfrom(65565)

    # packet string from tuple
    packet = packet[0]

    if eth_addr(packet[0:6]) == loc_mac or eth_addr(packet[6:12]) == loc_mac or eth_addr(
            packet[0:6]) == d_mac or eth_addr(packet[6:12]) == d_mac or eth_addr(packet[0:6]) == d_mac1 or eth_addr(packet[6:12]) == d_mac1:
        pass
    else:
        # parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        f.write( 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(
            packet[6:12]) + ' Protocol : ' + str(eth_protocol) + '\n')

        # Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8:
            # Parse IP header
            # take first 20 characters for the ip header
            ip_header = packet[eth_length:20 + eth_length]

            # now unpack them :)
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);

            f.write('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(
                ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(
                s_addr) + ' Destination Address : ' + str(d_addr) + '\n')

            # TCP protocol
            if protocol == 6:
                t = iph_length + eth_length
                tcp_header = packet[t:t + 20]

                # now unpack them :)
                tcph = unpack('!HHLLBBHHH', tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                f.write('Source Port : ' + str(source_port) + ' Dest Port : ' + str(
                    dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(
                    acknowledgement) + ' TCP header length : ' + str(tcph_length) + '\n')

                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                # get data from the packet
                data = packet[h_size:]

                f.write('Data : ' + data + '\n')

            # ICMP Packets
            elif protocol == 1:
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u + 4]

                # now unpack them :)
                icmph = unpack('!BBH', icmp_header)

                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                f.write('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum) + '\n')

                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size

                # get data from the packet
                data = packet[h_size:]

                f.write('Data : ' + data + '\n')

            # UDP packets
            elif protocol == 17:
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u + 8]

                # now unpack them :)
                udph = unpack('!HHHH', udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                f.write('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(
                    length) + ' Checksum : ' + str(checksum) + '\n')

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size

                # get data from the packet
                data = packet[h_size:]

                f.write('Data : ' + data + '\n')

            # some other IP packet like IGMP
            else:
                f.write('Protocol other than TCP/UDP/ICMP')

            f.write('\n')