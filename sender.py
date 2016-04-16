import sys
import socket
import select 
import threading
from struct import pack, unpack
from datetime import datetime

MSS = 128
buffer_size = 1024
ERTT = 0
timeout = 2 # 2 secs
last_packet_size = 0
final_seq = -1
fin_packet_seq = -1
fin_received = 0
current_sending = 0 # maintain # sending packets not to exceed window size
all_packets = dict() # dictionary: key = seq, value = data_buffer
sent_packets = dict() # dictionary: key = seq, value = time
acked_packets = dict() # dictionary: key = seq, value = time

def build_all_packets(file):
    f = open(file)
    seq = 0
    global last_packet_size
    while True:
        chunk = f.read(MSS)
        if chunk == "":
            break
        all_packets[seq] = chunk
        last_packet_size = len(chunk)
        seq += MSS
    


def carry(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)
 
def get_checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = ord(data[i]) + (ord(data[i+1]) << 8)
        s = carry(s, w)
    return ~s & 0xffff
 

def make_tcp_header(source_port, dst_port, seq, ack_seq, ack_flag, fin_flag, window_size, payload):
    size_of_header = 5 # 5 fields  
    syn = 0
    rst = 0
    psh = 0
    urg = 0
    urg_ptr = 0
 
    header_length = (size_of_header << 4) + 0
    tcp_flags = fin_flag + (syn << 1) + (rst << 2) + (psh <<3) + (ack_flag << 4) + (urg << 5)
    if fin_flag == 0:
        data = pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, 0, urg_ptr) + payload
    else: 
        data = pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, 0, urg_ptr)
    checksum = get_checksum(data)
    return pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, urg_ptr)


def write_log(log_filename, src_port, dest_port, seq, ack_seq, tcp_flags):
    if log_filename == "stdout":
            print "%s, %s, %s, %d, %d, %s, %d" % (datetime.now(), src_port, dest_port, seq, ack_seq , tcp_flags, ERTT)
    else:    
        try:
            f = open(log_filename,'a')
            f.write("%s, %s, %s, %d, %d, %s, %d\n" % (datetime.now(), src_port, dest_port, ack_seq, ack_seq , tcp_flags, ERTT)) 
            f.close()
        except:
            print "file %s not found" % log_filename 

def checksum_verify(header):
    (source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, urg_ptr)= unpack('!HHLLBBHHH' , header)
    data = pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, 0, urg_ptr)
    if checksum == get_checksum(data): # valid packet
        return 0
    else:
        return -1    

def handle_ack(header, log_filename):
    # FIXME: add checksum
    if checksum_verify(header) != 0:
        print "packet corruption"
        return

    global current_sending
    (source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, urg_ptr)= unpack('!HHLLBBHHH' , header)  
    write_log(log_filename, source_port, dst_port, seq, ack_seq, tcp_flags)      
    if ack_seq not in acked_packets:
        acked_packets[ack_seq] = datetime.now()
        current_sending -= 1
    else: # duplicate ack
        print "duplicate ack: %d\n" % ack_seq  

    return ack_seq

def timeout_checker(log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, window_size):
    if packet_seq == final_seq:
        check_seq = packet_seq + last_packet_size
    elif packet_seq == fin_packet_seq : # check if fin receiver
        if fin_received == 0:
            fin_header = make_tcp_header(ack_port_num, remote_port, packet_seq, 0, 0, 1, window_size, "")
            sock.sendto(fin_header, (remote_ip, remote_port))
            checker_register(log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, window_size) # register a timeout checker
            print "fin packet delever failed\n" 
            write_log(log_filename, ack_port_num, remote_port, packet_seq, 0, 0)
            return
    else:
        check_seq = packet_seq + MSS    

    #print "timeout_checker check %d for seq %d " % (check_seq, packet_seq)
    
    if check_seq not in acked_packets: # packet lost timeout  
        tcp_header = make_tcp_header(ack_port_num, remote_port, packet_seq, 0, 0, 0, window_size, all_packets[packet_seq])
        sock.sendto(tcp_header + all_packets[packet_seq], (remote_ip, remote_port))
        checker_register(log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, window_size) # register a timeout checker
        print "timeout! check seq %d failed, resend seq: %d\n" % (check_seq, packet_seq)
        write_log(log_filename, ack_port_num, remote_port, packet_seq, 0, 0)

def checker_register(log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, window_size):
    t = threading.Timer(timeout, timeout_checker, [log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, window_size])
    t.daemon = True
    t.start()
   


''' sender <filename> <remote_IP> <remote_port> <ack_port_num> <log_filename> <window_size> '''
def main():    
    host = ''
    filename = sys.argv[1]
    remote_ip = sys.argv[2]
    remote_port = int(sys.argv[3])
    ack_port_num = int(sys.argv[4])
    log_filename = sys.argv[5]
    window_size = sys.argv[6]
    global final_seq
    global fin_packet_seq
    global fin_received

    print "<filename>%s <remote_IP>%s <remote_port>%d <ack_port_num>%d <log_filename>%s <window_size>%s " % (filename, remote_ip, remote_port, ack_port_num, log_filename, window_size)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    ack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    ack_sock.bind((host, ack_port_num))
    build_all_packets("test.txt")


    global current_sending
    sorted_index = sorted(all_packets)
    final_seq = sorted_index[-1]
    index_packets = 0
    while current_sending < int(window_size):
        if index_packets == len(sorted_index):
                break
        packet_seq = sorted_index[index_packets]
        tcp_header = make_tcp_header(ack_port_num, remote_port, packet_seq, 0, 0, 0, int(window_size), all_packets[packet_seq])
        sock.sendto(tcp_header + all_packets[packet_seq], (remote_ip, remote_port))
        sent_packets[packet_seq] = datetime.now()
        checker_register(log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, int(window_size)) # register a timeout checker
        write_log(log_filename, ack_port_num, remote_port, packet_seq, 0, 0) 
        index_packets += 1
        current_sending += 1

    print "start select, final_seq = %d" % final_seq
    sockets_listen = [ack_sock] # socket list for select 
    while True:
        inputready,outputready,exceptready = select.select(sockets_listen,[],[]) 
        for current in inputready:
            if current == ack_sock: # receive ACK packet
                data = current.recv(buffer_size) 
                handle_ack(data[:20], log_filename)
                if len(acked_packets) == len(all_packets):
                    fin_packet_seq = sorted(acked_packets)[-1]
                    fin_header = make_tcp_header(ack_port_num, remote_port, fin_packet_seq, 0, 0, 1, int(window_size), "")
                    sock.sendto(fin_header, (remote_ip, remote_port))   
                    checker_register(log_filename, sock, ack_port_num, remote_ip, remote_port, fin_packet_seq, int(window_size)) # register a timeout checker          
                    current.recv(buffer_size)
                    fin_received = 1
                    print "Delivery completed successfully"
                    sys.exit(0)

        while current_sending < int(window_size): # check window size and send new packets
            if index_packets == len(sorted_index):
                break
            packet_seq = sorted_index[index_packets]
            tcp_header = make_tcp_header(ack_port_num, remote_port, packet_seq, 0, 0, 0, int(window_size), all_packets[packet_seq])
            sock.sendto(tcp_header + all_packets[packet_seq], (remote_ip, remote_port)) 
            sent_packets[packet_seq] = datetime.now()
            checker_register(log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, int(window_size)) # register a timeout checker
            write_log(log_filename, ack_port_num, remote_port, packet_seq, 0, 0) 
            index_packets += 1
            current_sending += 1

if __name__ == '__main__': 
    try:
        main()
    except KeyboardInterrupt:
        print len(all_packets)
        print len(acked_packets)
        print '\nserver receive ctrl+C\n'














