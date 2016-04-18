COMMANDS:
	Sender: 
		python sender.py <filename> <remote_IP> <remote_port> <ack_port_num> <log_filename> <window_size>

	Receiver:
		python receiver.py <filename> <listening_port> <sender_IP> <sender_port> <log_filename>


(a) the TCP segment structure used 
	1. MSS can be change with global variable: MSS
	2. Each packet's payload is MSS except the last packet.
	3. Sequence number us based on payload length (i.e. Sender send seq#0 with payload = 128,  Receiver should ack 128 back).

(b) the states typically visited by a sender and receiver 
	Sender:
		1. At start, sending packets according to window size.
		2. Increase current_sending whenever sendgin a new packet.
	   	   Resending a timeout packet won't increase this number.
		3. When receiving a new ACK, decrease current_sending number.  
		4. When finish sending a packet, Sender will register an acked packet checker with an auto-calculated timeout value.
	       If the time is out and the ack packet was not yet received, register another timer for another timeout check.
	    5. When all the packets are acked, sending a fin packet and make sure this packet is received to terminate the transfer.   

	Receiver:
		1. Acked all new packets received except for duplicate packets or corrupted packets
		2. Record all data received in a dictionary: recv_packets
		3. When received a fin packet, send ack to Sender and start to reassemble the file then exit. 		   

(c) the loss recovery mechanism
	Selective-Repeat mechanism:
		Only resend the timeout packet