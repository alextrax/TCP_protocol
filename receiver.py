import sys
import socket
from struct import unpack, pack
from datetime import datetime

buffer_size = 1024
next_expect_seq = 0
recv_packets = dict() # dictionary: key = seq, value = data_buffer

def build_file(filename):
    f = open(filename, 'w')
    sorted_index = sorted(recv_packets)
    for i in sorted_index:
        f.write(recv_packets[i])

def make_tcp_header(source_port, dst_port, seq, ack_seq, ack_flag, fin_flag, checksum, window_size):
    size_of_header = 5 # 5 fields  
    syn = 0
    rst = 0
    psh = 0
    urg = 0
    check = 0
    urg_ptr = 0
 
    header_length = (size_of_header << 4) + 0
    tcp_flags = fin_flag + (syn << 1) + (rst << 2) + (psh <<3) + (ack_flag << 4) + (urg << 5)
    return pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, urg_ptr)

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
            
def handle_packet(header, log_filename):
    (source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, urg_ptr)= unpack('!HHLLBBHHH' , header)
    write_log(log_filename, source_port, dst_port, seq, ack_seq, tcp_flags)           
    return seq

    

''' receiver <filename> <listening_port> <sender_IP> <sender_port> <log_filename> '''
def main():    
    host = ''
    filename = sys.argv[1]
    listening_port = int(sys.argv[2])
    sender_IP = sys.argv[3]
    sender_port = int(sys.argv[4])
    log_filename = sys.argv[5]
    global next_expect_seq

    print "<filename>%s <listening_port>%d <sender_IP>%s <sender_port>%d <log_filename>%s " % (filename, listening_port, sender_IP, sender_port, log_filename)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    sock.bind((host, listening_port))
    ack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 

    while True:
        data, addr = sock.recvfrom(buffer_size) 
        seq = handle_packet(data[:20], log_filename) # header = data[:20], payload = data[20:]

        if seq == next_expect_seq and 1: # FIXME: add checksum
            recv_packets[seq] = data[20:]
            ack_seq = seq + len(data[20:]) 
            next_expect_seq = ack_seq
            tcp_header = make_tcp_header(listening_port, sender_port, 0, ack_seq, 1, 0, 99, 5)
            ack_sock.sendto(tcp_header, (sender_IP, sender_port)) # send ACK packet
            write_log(log_filename, listening_port, sender_port, 0, ack_seq, 1<<4)
        elif seq in recv_packets and 1: # duplicate packets # FIXME: add checksum
            pass

        else:  # packet lost or corrupt 
            ack_seq = next_expect_seq
            tcp_header = make_tcp_header(listening_port, sender_port, 0, ack_seq, 1, 0, 99, 5)
            ack_sock.sendto(tcp_header, (sender_IP, sender_port)) # send ACK packet
            write_log(log_filename, listening_port, sender_port, 0, ack_seq, 1<<4)

        

if __name__ == '__main__': 
    try:
        main()
    except KeyboardInterrupt:
        print '\nserver receive ctrl+C\n'
        build_file("output.txt")