import socket, sys, commands 

#controller default PORT and IP
UDP_IP = 'controller'
UDP_PORT = 7777
UDP_INP_PORT=5005

#Server hello message data
hostname = commands.getoutput("hostname")
interface = commands.getoutput("ip -o route get 10.10.10.10 | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}'")
mac_address = commands.getoutput("cat /sys/class/net/" + interface + "/address")
message = "Hello"# + ";" + hostname + ";" + mac_address

#send the message
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
sock.bind(('', UDP_INP_PORT))
sock.sendto(message, (UDP_IP, UDP_PORT))
while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    print "received message:", data
