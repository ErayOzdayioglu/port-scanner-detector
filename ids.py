import socket
import struct
import time
import logging

closed_ports = set()
ips_and_ports = []

def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    proto = socket.htons(prototype)
    data = raw_data[14:]
    return proto, data 

def find_closed_ports():
    
    for port in range(1,65535):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex(("127.0.0.1", port))
        if result != 0:
            closed_ports.add(port)
        sock.close()



def get_ip(addr):
     return '.'.join(map(str, addr))

def syn_to_non_listening_port(ip):
    logging.basicConfig(filename='ids.log',level=logging.DEBUG)
    logging.warning('IP Address: %s Signature: SYN to non-listening port',ip)
   

def check_is_closed(port):
    return port in closed_ports

def check_is_encountered(item):
    for x in ips_and_ports:
        if (item["ip"] == x["ip"] and item["destination_port"] != x["destination_port"] and (item["time"] - x["time"]) < 180):
            logging.basicConfig(filename='ids.log',level=logging.DEBUG)
            logging.warning('IP Address %s Signature: Several packets from same source to different ports in short amount of time',item["ip"])
            return True
    ips_and_ports.append(item)
    return False



def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src = get_ip(src)
    target = get_ip(target)
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, src, target, data

def find_local_ip():
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP
    

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
    find_closed_ports()
    
    s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    
    local_ip = find_local_ip()
    
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data)

        if (eth[0] == 8):
            ipv4 = ipv4_head(eth[1])
            protocol = ipv4[3]
            source_ip = ipv4[4]
            target_ip = ipv4[5] 
            if (protocol == 6 and target_ip == local_ip):
                tcp = tcp_head(ipv4[6])
            
                destination_port = tcp[1]
                item = {
                    "ip" : source_ip,
                    "destination_port" : destination_port,
                    "time" : time.time()
                }
             
                check_is_encountered(item)
                if(check_is_closed(tcp[1]) and tcp[8] == 1 ):
                    syn_to_non_listening_port(ipv4[4])




main()

