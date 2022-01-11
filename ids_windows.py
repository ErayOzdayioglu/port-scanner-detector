import socket
import struct
import threading
import concurrent.futures
import time

closed_ports = {}
ips_and_ports = []

def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    proto = socket.htons(prototype)
    data = raw_data[14:]
    return proto, data 

def find_closed_ports(port):
    
      
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex(("127.0.0.1", port))
    if result != 0:
        closed_ports.add(port)
    sock.close()

with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    for port in range(1000):
        executor.submit(find_closed_ports,port)


def get_ip(addr):
     return '.'.join(map(str, addr))

def syn_to_non_listening_port(ip):
    print("IP Address: " + ip + " Signature: SYN to non-listening port")

def check_is_closed(port):
    return port in closed_ports

def check_is_encountered(item):
    for x in ips_and_ports:
        if (item["ip"] == x["ip"] and item["destination_port"] != x["destination_port"] and (item["time"] - x["time"]) < 180):
            print("IP Address: " + item["ip"] + " Signature: signature 2")
            return False
    ips_and_ports.append(item)
    return True



def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src = get_ip(src)
    target = get_ip(target)
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, src, target, data

def tcp_head( raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, data

def main():
    
    
    
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data)
        if (eth[0] == 8):
            ipv4 = ipv4_head(eth[1])
            print( '\t - ' + 'IPv4 Packet:')
            print('\t\t - ' + 'Version: {}, Header Length: {}, TTL:{},'.format(ipv4[0], ipv4[1], ipv4[2]))
            print('\t\t - ' + 'Protocol: {}, Source: {}, Target:{}'.format(ipv4[3], ipv4[4], ipv4[5]))
            if (ipv4[3] == 6):
                tcp = tcp_head(ipv4[6])
                print('TCP Segment:')
                print('Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
                print('Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
                print('Flags:')
                print('URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
                print('RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))
                item = {
                    "ip" : ipv4[4],
                    "destination_port" : tcp[1],
                    "time" : time.time()
                }
                check_is_encountered(item)
                if(check_is_closed(tcp[1]) and tcp[8] == 1 ):
                    syn_to_non_listening_port(ipv4[4])




main()

