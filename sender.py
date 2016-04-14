import sys
import socket
from struct import pack

MSS = 16

all_packets = dict() # dictionary: key = seq, value = data_buffer
sent_packets = dict() # dictionary: key = seq, value = time
acked_packets = dict() # dictionary: key = seq, value = time

def build_all_packets(file):
    f = open(file)
    seq = 0
    while True:
        chunk = f.read(MSS)
        if chunk == "":
            break
        all_packets[seq] = chunk
        seq += MSS

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


''' sender <filename> <remote_IP> <remote_port> <ack_port_num> <log_filename> <window_size> '''
def main():    
    host = ''
    filename = sys.argv[1]
    remote_ip = sys.argv[2]
    remote_port = int(sys.argv[3])
    ack_port_num = int(sys.argv[4])
    log_filename = sys.argv[5]
    window_size = sys.argv[6]

    print "<filename>%s <remote_IP>%s <remote_port>%d <ack_port_num>%d <log_filename>%s <window_size>%s " % (filename, remote_ip, remote_port, ack_port_num, log_filename, window_size)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    tcp_header = make_tcp_header(ack_port_num, remote_port, 0, 0, 0, 0, 99, 5)
    sock.sendto(tcp_header + "hello udp", (remote_ip, remote_port))
    build_all_packets("test.txt")
    sorted_index = sorted(all_packets)
    for i in sorted_index:
        print(all_packets[i])


if __name__ == '__main__': 
    try:
        main()
    except KeyboardInterrupt:
        print '\nserver receive ctrl+C\n'