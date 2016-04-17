import sys
import socket
from struct import unpack, pack
from datetime import datetime

buffer_size = 1024
transfer_finished = 0
recv_packets = dict() # dictionary: key = seq, value = data_buffer

def build_file(filename):
    f = open(filename, 'w')
    sorted_index = sorted(recv_packets)
    for i in sorted_index:
        f.write(recv_packets[i])


def make_tcp_header(source_port, dst_port, seq, ack_seq, ack_flag, fin_flag, window_size):
    header_length = (5 << 4)
    tcp_flags = fin_flag + (ack_flag << 4)
    data = pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, 0, 0)
    checksum = get_checksum(data)
    #print checksum
    return pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, 0)

def write_log(log_filename, src_port, dest_port, seq, ack_seq, tcp_flags):
    if log_filename == "stdout":
            print "%s, %s, %s, %d, %d, %s" % (datetime.now(), src_port, dest_port, seq, ack_seq , tcp_flags)
    else:    
        try:
            f = open(log_filename,'a')
            f.write("%s, %s, %s, %d, %d, %s\n" % (datetime.now(), src_port, dest_port, ack_seq, ack_seq , tcp_flags)) 
            f.close()
        except:
            print "file %s not found" % log_filename 


def carry(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)
 
def get_checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = ord(data[i]) + (ord(data[i+1]) << 8)
        s = carry(s, w)
    return ~s & 0xffff

def handle_packet(header, payload, log_filename):
    (source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, urg_ptr)= unpack('!HHLLBBHHH' , header)
    write_log(log_filename, source_port, dst_port, seq, ack_seq, tcp_flags)  
    return seq

def checksum_verify(data):
    (source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, urg_ptr)= unpack('!HHLLBBHHH' , data[:20])
    data_checksum_zero = pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, 0, urg_ptr) + data[20:]
    global transfer_finished
    if checksum == get_checksum(data_checksum_zero): # valid packet   
        if tcp_flags & 0x1 == 1: # fin flag is 1
            transfer_finished = 1
        return 0
    else:
        print "packet corrupt %d != %d" %(get_checksum(data_checksum_zero), checksum)
        return -1  


def check_IPv4(addr):
    try:
        socket.inet_pton(socket.AF_INET, addr)
    except socket.error:
        return False
    return True    

def check_IPv6(addr):
    try:
        socket.inet_pton(socket.AF_INET6, addr)
    except socket.error:
        return False
    return True 

def create_sock_on_addr(addr):
    if check_IPv4(addr) == True:
        return socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    elif check_IPv6(addr) == True:
        return socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)  

''' receiver <filename> <listening_port> <sender_IP> <sender_port> <log_filename> '''
def main():    
    host = ''
    filename = sys.argv[1]
    listening_port = int(sys.argv[2])
    sender_IP = sys.argv[3]
    sender_port = int(sys.argv[4])
    log_filename = sys.argv[5]

    print "<filename>%s <listening_port>%d <sender_IP>%s <sender_port>%d <log_filename>%s " % (filename, listening_port, sender_IP, sender_port, log_filename)
    res = socket.getaddrinfo(sender_IP, sender_port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE)
    af, socktype, proto, cn, sockaddr = res[0]
    print sockaddr

    sock = create_sock_on_addr(sockaddr[0]) 
    sock.bind((host, listening_port))
    ack_sock = create_sock_on_addr(sockaddr[0])

    while True:
        if transfer_finished == 1:
            build_file(filename)
            tcp_header = make_tcp_header(listening_port, sender_port, 0, 0, 1, 0, 1)
            ack_sock.sendto(tcp_header, sockaddr) # send ACK for receiving fin
            print "Delivery completed successfully"
            break
        data, addr = sock.recvfrom(buffer_size) 
        seq = handle_packet(data[:20], data[20:], log_filename) # header = data[:20], payload = data[20:]
        if checksum_verify(data) != 0:
            continue

        if seq not in recv_packets: # FIXME: add checksum
            recv_packets[seq] = data[20:]
            ack_seq = seq + len(data[20:]) 
            tcp_header = make_tcp_header(listening_port, sender_port, 0, ack_seq, 1, 0, 1)
            ack_sock.sendto(tcp_header, sockaddr) # send ACK packet
            write_log(log_filename, listening_port, sender_port, 0, ack_seq, 1<<4)
        else: # duplicate packets # FIXME: add checksum
            pass
'''
        else:  # packet lost or corrupt 
            ack_seq = next_expect_seq
            tcp_header = make_tcp_header(listening_port, sender_port, 0, ack_seq, 1, 0, 99, 5)
            ack_sock.sendto(tcp_header, (sender_IP, sender_port)) # send ACK packet
            write_log(log_filename, listening_port, sender_port, 0, ack_seq, 1<<4)
'''
        

if __name__ == '__main__': 
    try:
        main()
    except KeyboardInterrupt:
        print '\nserver receive ctrl+C\n'
        #build_file("output.txt")