#!/bin/bash
# Remove output file
#rm output.txt
#start test with netcat
#./bin/check_http & nc 127.0.0.1 9090 < input.txt > output.txt

#run test against curl
./bin/myproxy 9090 forbidden.txt log.txt & 
curl -v -x http://127.0.0.1:9090 http://www.example.com -o output3.txt 2>> curlout.txt 
curl -v -x http://127.0.0.1:9090 http://web.mit.edu -o output4.txt 2>> curlout.txt

#curl -v -x http://127.0.0.1:9090 http://web.mit.edu -o output4.txt & 
#lldb ./bin/check_http 
#./bin/check_http & curl -v -x http://127.0.0.1:9090 http://www.example.com -o output3.txt  