import sys
import socket
from struct import unpack

recv_packets = dict() # dictionary: key = seq, value = data_buffer

def build_file(filename):
    sorted_index = sorted(recv_packets)
    for i in sorted_index:
        print(recv_packets[i])

''' receiver <filename> <listening_port> <sender_IP> <sender_port> <log_filename> '''
def main():    
    host = ''
    filename = sys.argv[1]
    listening_port = int(sys.argv[2])
    sender_IP = sys.argv[3]
    sender_port = int(sys.argv[4])
    log_filename = sys.argv[5]

    print "<filename>%s <listening_port>%d <sender_IP>%s <sender_port>%d <log_filename>%s " % (filename, listening_port, sender_IP, sender_port, log_filename)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    sock.bind((host, listening_port))

    while True:
        data, addr = sock.recvfrom(4096) 
        (source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, urg_ptr)= unpack('!HHLLBBHHH' , data[:20])
        print "source_port %d, dst_port %d, seq %d, ack_seq %d, header_length %d, tcp_flags %s,  window_size %d, checksum %d, tcp_urg_ptr %d" % (source_port, dst_port, seq, ack_seq, header_length >> 4, tcp_flags,  window_size, checksum, urg_ptr)
        print "received message:", data[20:]
        print len(data[20:])


if __name__ == '__main__': 
    try:
        main()
    except KeyboardInterrupt:
        print '\nserver receive ctrl+C\n'