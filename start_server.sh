#######HEADER  (CHANGE HOSTS) ##########
server1="<host1>" # put here the server URLs that are allocated for the slice, example: server1="pc1.geni.uchicago.edu"
server2="<host2>"
server3="<host3>"
date="2001-01-01" # put here the date from which you want to start the green energy emulation 
		  # (it must be 2001 year, and the format is YYYY-MM-DD)

######REMOTE SSH (CHANGE PORTS FOR SERVER-1, SERVER-2, ...., SERVER-9) #######

# these commands first delete the previous python process, then run server.py script.
# you need to change the ports for succesfull ssh
# first command must be done on server-1, second - on server-2, and so on.

ssh -f -n grigorg@${server1} -p 33341 "sudo pkill python; cd /tmp/server; python server.py 1 $date;"
echo "done"
ssh -f -n grigorg@${server1} -p 33342 "sudo pkill python; cd /tmp/server; python server.py 2 $date;"
echo "done"
ssh -f -n grigorg@${server1} -p 33343 "sudo pkill python; cd /tmp/server; python server.py 3 $date;"
echo "done"
ssh -f -n grigorg@${server2} -p 33341 "sudo pkill python; cd /tmp/server; python server.py 4 $date;"
echo "done"
ssh -f -n grigorg@${server2} -p 33342 "sudo pkill python; cd /tmp/server; python server.py 5 $date;"
echo "done"
ssh -f -n grigorg@${server2} -p 33343 "sudo pkill python; cd /tmp/server; python server.py 6 $date;"
echo "done"
ssh -f -n grigorg@${server3} -p 33342 "sudo pkill python; cd /tmp/server; python server.py 7 $date;"
echo "done"
ssh -f -n grigorg@${server3} -p 33343 "sudo pkill python; cd /tmp/server; python server.py 8 $date;"
echo "done"
ssh -f -n grigorg@${server3} -p 33344 "sudo pkill python; cd /tmp/server; python server.py 9 $date;"
echo "done"
