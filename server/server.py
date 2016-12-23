import socket, sys, commands, re
import random, time, math

#controller default PORT and IP
UDP_IP = 'controller'
UDP_PORT_HELLO = 7777
UDP_PORT_INFO = 7778
UDP_OUT_PORT=5005

estE = 0.0 
devE = 0.0

def getGreenEnergyValue():
  global estE
  global devE 
  bs=10
  alpha = 0.125
  betha = 0.25
  sampleE = random.uniform(1,10)*bs
  if (estE == 0):
    estE = sampleE
  else:
    estE = (1 - alpha)*estE + alpha*sampleE
  return estE, bs*10

def getDelayValue():
  return 10, 10

def getCPUValue():
  return 10, 10


def main():
  #Server hello message
  message = "Hello"# + ";" + hostname + ";" + mac_address

  #send the message
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
  sock.bind(('', UDP_OUT_PORT))
  sock.sendto(message, (UDP_IP, UDP_PORT_HELLO))

  data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
  print "received message:", data
  split_line = re.split(';',data)
  parameters = tuple(re.split(',',split_line[0]))
  timeout = int(split_line[1])
  id = split_line[2]
  print "Timeout", timeout
  print "Parameters", parameters

  v = 0.0
  metrics = 0
  while True:
    message=''
    for p in parameters:
      if (p == 'GE'):
        v, metrics = getGreenEnergyValue()
      elif (p == 'DL'):
        v, metrics = getDelayValue()
      elif (p == 'CPU'):
        v, metrics = getCPUValue()  
      message += str(v) + ',' #sending only value for now
    message = message[:-1] + ";" + id 
    sock.sendto(message, (UDP_IP, UDP_PORT_INFO))
    time.sleep(int(timeout))    

if __name__ == "__main__":
  main()


      
