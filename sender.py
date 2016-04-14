import sys
import socket
import select 
from struct import pack, unpack

MSS = 128
buffer_size = 1024
current_sending = 0 # maintain # sending packets not to exceed window size
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

def handle_ack(header):
    global current_sending
    current_sending -= 1
    (source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, urg_ptr)= unpack('!HHLLBBHHH' , header)
    print "ACK: source_port %d, dst_port %d, seq %d, ack_seq %d, header_length %d, tcp_flags %s,  window_size %d, checksum %d, tcp_urg_ptr %d" % (source_port, dst_port, seq, ack_seq, header_length >> 4, tcp_flags,  window_size, checksum, urg_ptr)
 

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
    ack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    ack_sock.bind((host, ack_port_num))
    build_all_packets("test.txt")


    global current_sending
    sorted_index = sorted(all_packets)
    index_packets = 0
    while current_sending < int(window_size):
        if index_packets == len(sorted_index):
                break
        packet_seq = sorted_index[index_packets]
        tcp_header = make_tcp_header(ack_port_num, remote_port, packet_seq, 0, 0, 0, 99, 5)
        sock.sendto(tcp_header + all_packets[packet_seq], (remote_ip, remote_port))
        print "SEND: seg = %d"%packet_seq
        index_packets += 1
        current_sending += 1

    print "start select"
    sockets_listen = [ack_sock] # socket list for select 
    while True:
        inputready,outputready,exceptready = select.select(sockets_listen,[],[]) 
        for current in inputready:
            if current == ack_sock: # receive ACK packet
                data = current.recv(buffer_size) 
                handle_ack(data[:20])

        while current_sending < int(window_size):
            if index_packets == len(sorted_index):
                break
            packet_seq = sorted_index[index_packets]
            tcp_header = make_tcp_header(ack_port_num, remote_port, packet_seq, 0, 0, 0, 99, 5)
            sock.sendto(tcp_header + all_packets[packet_seq], (remote_ip, remote_port))
            print "SEND: seg = %d"%packet_seq
            index_packets += 1
            current_sending += 1

if __name__ == '__main__': 
    try:
        main()
    except KeyboardInterrupt:
        print '\nserver receive ctrl+C\n'














