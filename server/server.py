import socket, sys, commands, re
import random, time, math
import xlrd, datetime

#controller default PORT and IP
UDP_IP = 'controller-host'
UDP_PORT_HELLO = 7777
UDP_PORT_INFO = 7778
UDP_OUT_PORT=5005

def datetime_to_excel(date):
    temp = datetime.datetime(1899, 12, 30)
    delta = date - temp
    return (delta.days + delta.seconds / 86400)

def getGreenEnergyValue(location_id, worksheet, row):
  energyValue = worksheet.cell(row,location_id).value
  return float(energyValue)

def getDelayValue():
  return 10

def getCPUValue():
  return 10


def main():
  print "Excel parsing"
  workbook = xlrd.open_workbook('Solar_Test.xlsx')
  worksheet = workbook.sheet_by_index(0)
  input_date = datetime.datetime.strptime(sys.argv[2] + "-00-00", "%Y-%m-%d-%H-%M")
  date = datetime_to_excel(input_date)
  location_id = int(sys.argv[1])
  print "Location ID is", location_id
  date_counter = 1
  row = 1

  print "Get the date"
  while True:
   cell_data = getGreenEnergyValue(0,worksheet,date_counter)
   if not cell_data:
     date_counter = date_counter + 1
   elif(int(cell_data) == date):
     row = date_counter
     break
   else:
     date_counter = date_counter + 1
  #

  #Server hello message
  message = "Hello"# + ";" + hostname + ";" + mac_address

  print "send the hello message"
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
  sock.bind(('', UDP_OUT_PORT))
  sock.settimeout(5)
  while True:
    sock.sendto(message, (UDP_IP, UDP_PORT_HELLO))
    print "Sending hello message"
    time.sleep(1)
    try:
      data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    except socket.timeout:
        print "No response from controller"
        continue
    if data=="404":
       continue
    break
  print "received message:", data
  split_line = re.split(';',data)
  parameters = tuple(re.split(',',split_line[0]))
  timeout = int(split_line[1])
  id = split_line[2]
  print "Timeout", timeout
  print "Parameters", parameters
  
  sock.settimeout(100)
  v = 0.0
  metrics = 0
  while True:
    message=''
    for p in parameters:
      if (p == 'GE'):
        v_temp = getGreenEnergyValue(location_id, worksheet, row)
        v = float(v_temp)
        print v
      elif (p == 'DL'):
        v = getDelayValue()
      elif (p == 'CPU'):
        v = getCPUValue()  
      message += str(v) + ',' #sending only value for now
    message = message[:-1] + ";" + id 
    sock.sendto(message, (UDP_IP, UDP_PORT_INFO))
    try:
      data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    except socket.timeout:
        print "Send it again"
        continue
    if data == "404":
        return
    
    print "OK received"
    row += 1 #jumping
    time.sleep(int(timeout))    

if __name__ == "__main__":
 while True:
   main()
      
