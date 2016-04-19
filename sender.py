import sys
import socket
import select 
import threading
from struct import pack, unpack
from datetime import datetime

MSS = 128
buffer_size = 1024
ERTT = 0 
devRTT = 0
timeout = 3 # initial 3 secs ref: http://www.rfc-base.org/txt/rfc-6298.txt
final_seq = -1
fin_packet_seq = -1
fin_received = 0
current_sending = 0 # maintain # sending packets not to exceed window size
sent_bytes = 0
sent_count = 0
retransmit_count = 0

all_packets = dict() # dictionary: key = seq, value = data_buffer
sent_packets = dict() # dictionary: key = seq, value = time
acked_packets = dict() # dictionary: key = seq, value = time

lock_byte = threading.Lock()
lock_retransmit = threading.Lock()

def increase_sent_byte(length):
    global sent_bytes
    global sent_count 
    lock_byte.acquire()
    try:
        sent_count += 1  
        sent_bytes += length
    finally:
        lock_byte.release()

def increase_retransmit():
    global retransmit_count
    lock_retransmit.acquire()
    try:
        retransmit_count += 1  
    finally:
        lock_retransmit.release()


def build_all_packets(file):
    f = open(file)
    seq = 0
    global fin_packet_seq
    while True:
        chunk = f.read(MSS)
        if chunk == "":
            break
        all_packets[seq] = chunk
        seq += 1
    fin_packet_seq = seq 

def get_checksum(data):
    checksum = 0
    for i in range(0, len(data), 2):
        w =((ord(data[i])<<8) & 0xFF00)+ ord(data[i+1])
        checksum += w
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xffff

def make_tcp_header(source_port, dst_port, seq, ack_seq, ack_flag, fin_flag, window_size, payload):
    header_length = (5 << 4)
    tcp_flags = fin_flag + (ack_flag << 4) 
    if payload != "":
        data = pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, 0, 0) + payload
    else: 
        data = pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, 0, 0)
    checksum = get_checksum(data)
    return pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, 0)


def write_log(log_filename, src_port, dest_port, seq, ack_seq, tcp_flags):
    if log_filename == "stdout":
            print "%s, %s, %s, %d, %d, %s, %f" % (datetime.now(), src_port, dest_port, seq, ack_seq , tcp_flags, ERTT/1000000)
    else:    
        try:
            f = open(log_filename,'a')
            f.write("%s, %s, %s, %d, %d, %s, %f\n" % (datetime.now(), src_port, dest_port, seq, ack_seq , tcp_flags, ERTT/1000000)) 
            f.close()
        except:
            print "file %s not found" % log_filename 

def checksum_verify(header):
    (source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, urg_ptr)= unpack('!HHLLBBHHH' , header)
    data = pack('!HHLLBBHHH' , source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, 0, urg_ptr)
    if checksum == get_checksum(data): # valid packet
        return 0
    else:
        print "%d != %d" % (checksum, get_checksum(data))
        return -1    

def update_ERTT(diff_usec):
    '''
    Ref: http://www.rfc-base.org/txt/rfc-6298.txt
    When the first RTT measurement R is made, the host MUST set

            SRTT <- R
            RTTVAR <- R/2
    '''
    global ERTT
    global devRTT
    if ERTT == 0 : # first RTT
        ERTT = diff_usec
        devRTT = diff_usec/2
    else:
        a = 0.125
        ERTT = (1 - a) * ERTT + a * diff_usec

def update_devRTT(diff_usec):
    global devRTT
    b = 0.25
    devRTT = (1-b) * devRTT + b * abs(diff_usec-ERTT)

def update_timeout(diff_usec):
    global ERTT
    global devRTT
    global timeout
    update_ERTT(diff_usec)
    update_devRTT(diff_usec)
    timeout = (ERTT + 4 * devRTT) / 1000000 # seconds
    #print "timeout = %f" % timeout

def handle_ack(header, log_filename):
    if checksum_verify(header) != 0:
        print "packet corruption"
        return

    global current_sending
    (source_port, dst_port, seq, ack_seq, header_length, tcp_flags,  window_size, checksum, urg_ptr)= unpack('!HHLLBBHHH' , header)  
    write_log(log_filename, source_port, dst_port, seq, ack_seq, tcp_flags)      
    if ack_seq not in acked_packets:
        now = datetime.now()
        acked_packets[ack_seq] = now
        sent_seq = ack_seq - 1

        diff = now - sent_packets[sent_seq]
        diff_usec = diff.days * 24 * 60*60 *1000000 + diff.seconds*1000000 + diff.microseconds
        #print "RTT = %d usec" % diff_usec
        update_timeout(diff_usec)
        current_sending -= 1
    else: # duplicate ack
        print "duplicate ack: %d\n" % ack_seq  

    return ack_seq

def timeout_checker(log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, window_size):
    if packet_seq == fin_packet_seq : # check if fin received
        if fin_received == 0:
            fin_header = make_tcp_header(ack_port_num, remote_port, packet_seq, 0, 0, 1, window_size, "")
            sock.sendto(fin_header, (remote_ip, remote_port))
            increase_sent_byte(len(fin_header))
            increase_retransmit()
            checker_register(log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, window_size) # register a timeout checker
            print "fin packet delever failed\n" 
            write_log(log_filename, ack_port_num, remote_port, packet_seq, 0, 1)
            return
    else:
        check_seq = packet_seq + 1    

    #print "timeout_checker check %d for seq %d " % (check_seq, packet_seq)
    
    if check_seq not in acked_packets: # packet lost timeout  
        tcp_header = make_tcp_header(ack_port_num, remote_port, packet_seq, 0, 0, 0, window_size, all_packets[packet_seq])
        sock.sendto(tcp_header + all_packets[packet_seq], (remote_ip, remote_port))
        increase_sent_byte(len(tcp_header + all_packets[packet_seq]))
        increase_retransmit()
        sent_packets[packet_seq] = datetime.now()
        checker_register(log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, window_size) # register a timeout checker
        print "timeout! check seq %d failed, resend seq: %d\n" % (check_seq, packet_seq)
        write_log(log_filename, ack_port_num, remote_port, packet_seq, 0, 0)

def checker_register(log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, window_size):
    print "checker timeout = %f" % timeout
    t = threading.Timer(timeout, timeout_checker, [log_filename, sock, ack_port_num, remote_ip, remote_port, packet_seq, window_size])
    t.daemon = True
    t.start()
   

def print_statistic():
    print "Delivery completed successfully"
    print "Total bytes sent = %d" % sent_bytes
    print "Segments sent = %d" % sent_count
    retrans_rate = (float(retransmit_count) / float(sent_count))*100
    print "Segments retransmitted = %.2f %%" % retrans_rate

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


''' sender <filename> <remote_IP> <remote_port> <ack_port_num> <log_filename> <window_size> '''
def main():    
    host = ''
    filename = sys.argv[1]
    remote_ip = sys.argv[2]
    remote_port = int(sys.argv[3])
    ack_port_num = int(sys.argv[4])
    log_filename = sys.argv[5]
    if len (sys.argv) < 7:
        window_size = 1
    else:
        window_size = sys.argv[6]
    global final_seq
    global fin_packet_seq
    global fin_received

    print "<filename>%s <remote_IP>%s <remote_port>%d <ack_port_num>%d <log_filename>%s <window_size>%s " % (filename, remote_ip, remote_port, ack_port_num, log_filename, window_size)

    try:
        res = socket.getaddrinfo(remote_ip, remote_port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE)
    except:
        print "invalid IP"
        sys.exit(0)
    af, socktype, proto, cn, sockaddr = res[0]
    print sockaddr

    sock = create_sock_on_addr(sockaddr[0])
    ack_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    ack_sock.bind((host, ack_port_num))
    build_all_packets(filename)


    global current_sending
    sorted_index = sorted(all_packets)
    final_seq = sorted_index[-1]
    index_packets = 0
    while current_sending < int(window_size):
        if index_packets == len(sorted_index):
                break
        packet_seq = sorted_index[index_packets]
        tcp_header = make_tcp_header(ack_port_num, remote_port, packet_seq, 0, 0, 0, int(window_size), all_packets[packet_seq])
        sock.sendto(tcp_header + all_packets[packet_seq], sockaddr)
        increase_sent_byte(len(tcp_header + all_packets[packet_seq]))
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
                handle_ack(data, log_filename)
                if len(acked_packets) == len(all_packets): # send fin packet
                    fin_packet_seq = sorted(acked_packets)[-1]
                    fin_header = make_tcp_header(ack_port_num, remote_port, fin_packet_seq, 0, 0, 1, int(window_size), "")
                    sock.sendto(fin_header, sockaddr)   
                    increase_sent_byte(len(fin_header))
                    write_log(log_filename, ack_port_num, remote_port, packet_seq, 0, 1)
                    checker_register(log_filename, sock, ack_port_num, remote_ip, remote_port, fin_packet_seq, int(window_size)) # register a timeout checker          
                    current.recv(buffer_size)
                    fin_received = 1
                    print_statistic()
                    sys.exit(0)

        while current_sending < int(window_size): # check window size and send new packets
            if index_packets == len(sorted_index):
                break
            packet_seq = sorted_index[index_packets]
            tcp_header = make_tcp_header(ack_port_num, remote_port, packet_seq, 0, 0, 0, int(window_size), all_packets[packet_seq])
            sock.sendto(tcp_header + all_packets[packet_seq], sockaddr) 
            increase_sent_byte(len(tcp_header + all_packets[packet_seq]))
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
        print '\nreceive ctrl+C\n'














