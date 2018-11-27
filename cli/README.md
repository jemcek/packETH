# packETHcli

## NEWS 27.11.2018:
- added receiver option (mode -m -9) to count received packets sent by packETHcli or packETH
- added option to incluce pattern (predifined or custom) which can be checked by packETHcli in receiver mode if all packets that were sent were also correctly received at the receiver site
- nanoseconds support 

## WHAT IS NEW (7.11.2018)?
- different sending options (single, multi, ramp) splited in different modes now to be more user friendly
- added option to change packet rate while sending (ramp mode) in both directions
- added option to change packet size while sending (ramp mode) at constant pps or constant bandwidth
- option to select which packet should be sent in case there are many stored in pcap file 
- added option to specify time to transmit (not only number of packets)
- IDS test mode included in main repo 
- changed statistics from kbit/s to Mbit/s

## INSTALLATION: 

cd cli  
make

## USAGE:
Usage: ./packETHcli -m <mode > -i <interface> -f <file> [options]  

 There are 5 diffent modes, use ./packETHcli -m <mode> to get detailed help for particular mode 

   -m 1   - SEND PACKET ONCE (default mode): send packet from the pcap file once  
   -m 2   - SEND PACKET CONTINUOUSLY WITH CONSTANT RATE: send (first) packet from pcap file at constant rate  
   -m 3   - SEND PACKET CONTINUOUSLY WITH VARIABLE RATE (SPEED RAMP)  
   -m 4   - SEND PACKET CONTINUOUSLY WITH VARIABLE SIZE (SIZE RAMP)  
   -m 5   - SEND SEQUENCE OF PACKETS (IDS TEST MODE)  

 -f <file> - file name where packet is stored in pcap format (or attack definitions file in Snort rule format in mode 5)  
 -I <seconds> - time interval to display results (default 1s)  

FOR EXAMPLES SEE: ./packETHcli -e  

 -m 1   - SEND PACKET ONCE (default mode): send packet from the pcap file once  
          Usage: ./packETHcli -m 1 -i <interface> -f <file> [-c]  
          Optional parameter:    
               -c <number>  - seuence number of packet stored in pcap file (by default first packet will be sent)  
                              to see sequence numbers of packets inside pcap file: tcpdump -# -r filename
               -I <seconds> - time interval to display results (default 1s)
          Example: packETHcli -i lo -f packet.pcap

 -m 2   - SEND PACKET CONTINUOUSLY WITH CONSTANT RATE: send (first) packet from pcap file at constant rate
          Usage: ./packETHcli -m 2 -i <interface> -f <file> [options]
          Required parameters:
              Number of packets to send or duration in seconds (only one option possible)
               -n <number, 0> - number of packets to send or 0 for infinite
               -t <seconds> - seconds to transmit
              Delay between packets or sendrate (only one option possible)
               -D <ns>        - delay between packets in nano seconds;
               -d <us>        - delay between packets in micro seconds;
               -d 0           - maximum speed with counters
               -d -1          - maximum speed without counters
               -b <bandwidth> - desired sending rate in kbit/s
               -B <bandwidth> - desired sending rate in Mbit/s
          Optional parameters:
               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)
               -I <seconds> - time interval to display results (default 1s)
              Insert predifined pattern into packet:
               -x             - insert pattern "a9b8c7d6" and counter inside last 10 bytes of packet
              Insert custom pattern at custom positon and counter at custom position
               -q <offset>    - where should the pattern be (bytes offset)
               -w <pattern>   - what should be the pattern to match
               -o <offset>    - where should the inceremented counter be (bytes offset)

          Example: ./packETHcli -i eth0 -m 2 -B 100 -n 10000 -f p1.pcap

 -m 3   - SEND PACKET CONTINUOUSLY WITH VARIABLE RATE (SPEED RAMP)
          Usage: ./packETHcli -m 3 -i <interface> -f <file> [options]
          Required parameters:
              Number of packets to send or duration in seconds (only one option possible)
               -n <number, 0> - number of packets to send or 0 for infinite
               -t <seconds> - seconds to transmit
              Startrate, Stoprate, Steprate and Step duration (only one option possible):
               -z "<startrate stoprate steprate)" in kbit/s
               -Z "<startrate stoprate steprate)" in Mbit/s
              Step duration:
               -p <seconds> - period between steps in seconds
          Optional parameters:
               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)
               -I <seconds> - time interval to display results (default 1s)
              Insert predifined pattern into packet:
               -x             - insert pattern "a9b8c7d6" and counter inside last 10 bytes of packet
              Insert custom pattern at custom positon and counter at custom position
               -q <offset>    - where should the pattern be (bytes offset)
               -w <pattern>   - what should be the pattern to match
               -o <offset>    - where should the inceremented counter be (bytes offset)

          Example: ./packETHcli -i eth1 -m 3 -t 3600 -Z "500 100 1" -p 5 -f p1.pcap

 -m 4   - SEND PACKET CONTINUOUSLY WITH VARIABLE SIZE (SIZE RAMP)
          Usage: ./packETHcli -m 4 -i <interface> -f <file> [options]
          Required parameters:
              Number of packets to send or duration in seconds (only one option possible)
               -n <number, 0> - number of packets to send or 0 for infinite
               -t <seconds> - seconds to transmit
              Delay between packets or sendrate (only one option possible). Choose first option for constant pps and second one for constant bandwidth
               -d <us, 0> - delay between packets in micro seconds; select 0 for maximum speed
               -D <ns, 0, -1> - delay between packets in nano seconds; select 0 for maximum speed with counters; select -1 for max speed without counters)
               -b <bandwidth> - desired sending rate in kbit/s
               -B <bandwidth> - desired sending rate in Mbit/s
              Startsize, Stopsize, Stepsize and Step duration number
               -s "<startsize stopsize stepsize>" in bytes (please note that TCP&UDP checksums are not (yet :) ) recalculated!!!)
               -p <seconds> - period between steps in seconds
          Optional parameters:
               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)
               -I <seconds> - time interval to display results (default 1s)
              Insert predifined pattern into packet:
               -x             - insert pattern "a9b8c7d6" and counter inside last 10 bytes of packet
          Example: ./packETHcli -i eth1 -m 4 -d 2000 -n 0 -s "100 1500 100" -p 5 -f p1.pcap

 -m 9   - RECEIVER MODE: COUNT PACKETS (FROM packETHcli)
          Usage: ./packETHcli -m 9 -i <interface> [-x OR -o <offset counter> -q <offset pattern> -w <pattern>]
          Optional parameter:
          To count packets with predifined pattern sent by packETHcli use -x option on both sides (sender and receiver)  :
            -x   - Last 10 bytes in received packets will be checked for pattern "a8b7c7d6" and counter
          To count packets with custom pattern at custom positon and counter at custom position:
            -q <offset>   - where should the pattern be (bytes offset)
            -w <pattern>  - what should be the pattern to match
            -o <offset>   - where should the inceremented counter be (bytes offset)
          Examples:
          ./receiver -i eth0
          ./receiver -i eth0 -x
          ./receiver -i eth0 -o 60 -q 70 -w 12345678
