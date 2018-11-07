## INSTALL: make

Usage: ./packETHcli -m <mode > -i <interface> -f <file> [options]

## WHAT IS NEW?
- added option to change packet rate while sending (ramp mode) in both directions
- added option to change packet size while sending (ramp mode) at constant pps or constant bandwidth
- option to select which packet should be sent in case there are many stored in pcap file 
- added option to specify time to transmit (not only number of packets)
- IDS test mode included in main repo 


## USAGE:

./packETHcli -h

 <mode>:
    1   - SEND PACKET ONCE (default mode): send packet from the pcap file once
          Optional parameter:
               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)
                              to see sequence numbers of packets inside pcap file: tcpdump -# -r filename
          Example: packETHcli -i lo -f packet.pcap

    2   - SEND PACKET CONTINUOUSLY WITH CONSTANT RATE: send (first) packet from pcap file at constant rate
          Parameters:
              Number of packets to send or duration in seconds (only one option possible)
               -n <number, 0> - number of packets to send or 0 for infinite
               -t <seconds> - seconds to transmit
              Delay between packets or sendrate (only one option possible)
               -d <us, 0, -1> - delay between packets in micro seconds; select 0 for maximum speed with counters; 
                                select -1 for max speed without counters)
               -b <bandwidth> - desired sending rate in kbit/s
               -B <bandwidth> - desired sending rate in Mbit/s
          Optional parameter:
               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)
          Example: ./packETHcli -i eth0 -m 2 -B 100 -n 10000 -f p1.pcap

    3   - SEND PACKET CONTINUOUSLY WITH VARIABLE RATE (SPEED RAMP):
          Parameters:
              Number of packets to send or duration in seconds (only one option possible)
               -n <number, 0> - number of packets to send or 0 for infinite
               -t <seconds> - seconds to transmit
              Startrate, Stoprate, Steprate and Step duration (only one option possible):
               -z "<startrate stoprate steprate)" in kbit/s
               -Z "<startrate stoprate steprate)" in Mbit/s
              Step duration:
               -p <seconds> - period between steps in seconds
          Optional parameter:
               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)
          Example: ./packETHcli -i eth1 -m 3 -t 3600 -Z "500 100 1" -p 5 -f p1.pcap

    4   - SEND PACKET CONTINUOUSLY WITH VARIABLE SIZE (SIZE RAMP)
          Parameters:
              Number of packets to send or duration in seconds (only one option possible)
               -n <number, 0> - number of packets to send or 0 for infinite
               -t <seconds> - seconds to transmit
              Delay between packets or sendrate (only one option possible). 
              Choose first option for constant pps and second one for constant bandwidth
               -d <us, 0> - delay between packets in micro seconds; select 0 for maximum speed
               -b <bandwidth> - desired sending rate in kbit/s
               -B <bandwidth> - desired sending rate in Mbit/s
              Startsize, Stopsize, Stepsize and Step duration number
               -s "<startsize stopsize stepsize>" in bytes (TCP&UDP checksums are not (yet :) ) recalculated!!!)
               -p <seconds> - period between steps in seconds
          Optional parameter:
               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)
          Example: ./packETHcli -i eth1 -m 4 -d 2000 -n 0 -s "100 1500 100" -p 5 -f p1.pcap

    5   - SEND SEQUENCE OF PACKETS (IDS TEST MODE)
          Parameters
            -f <attack definitions file in Snort rule format>
            -a <numbers from 0 to 4> - innocent traffic for 0, 25% attack for 1, 50% attack for 2, 
                                       75% attack for 3, 100% attack for 4
            -S <packet size in bytes OR -s "<startsize stopsize stepsize>" -p <step period>
            -d <us, 0, -1> - delay between packets OR -b <bandwidth in kbit/s>  OR -B <bandwidth in Mbit/s
            -n <number, 0> - number of packets to send (0 for infinite) OR -t <duration in seconds>
           Example: ./packETHcli -i lo -f sample_snort_rules.txt -B 10 -m 5 -t 60 -S 1000 -a 2

 -f <file> - file name where packet is stored in pcap format (or attack definitions file in Snort rule format in mode 5)


## Examples: ./packETHcli -e

All examples assume that we send on interface eth0 and that the packet is stored in file p1.pcap

###  mode 1 - send one packet and exit:
   - send packet p1.pcap once on interface eth0. 
     ./packETHcli -i eth0 -f p1.pcap                                               
   - send 5th packet from file p10.pcap. 
     ./packETHcli -i eth0 -f p10.pcap -c 5 

###  mode 2 - send packets at constant rate:
   - send 5th packet from file p10.pcap
     ./packETHcli -i eth0 -m 2 -d 0 -n 0 -f p1.pcap> 
   - send at max speed, infinite times, no counters
     ./packETHcli -i eth0 -m 2 -d -1 -n 0 -f p1.pcap  
   - send 300 packets with 1000 us (1ms) between them
     ./packETHcli -i eth0 -m 2 -d 1000 -n 300 -f p1.pcap 
   - send packets with rate 1500 kbit/s for 30s
     ./packETHcli -i eth0 -m 2 -b 1500 -t 30 -f p1.pcap 
   - send 7th packet 10000 times, with rate 100 Mbit/s
     ./packETHcli -i eth0 -m 2 -B 100 -n 10000 -f p1.pcap -c 7 

###  mode 3 - send packets with different rates (speed ramp):
   - start sendind at 100kbit/s for 10s, then increase rate by 100kbit/s each 10s up to 1500 kbit/s
     ./packETHcli -i eth1 -m   -n 0 -z "100 1500 100" -p 10 -f p1.pcap             
   - send with 500Mbit/s for 5s, then decrease rate by 1Mbit/s each 5s. Stop after 3600s if not finished
     ./packETHcli -i eth1 -m 3 -t 3600 -Z "500 100 1" -p 5 -f p1.pcap              

###  mode 4 - send packets with variable size (size ramp):
   - send at max speed, start with packet size of 100 bytes for 10s then increase by 100 bytes up to 1500 bytes
     ./packETHcli -i eth1 -m 4 -d 0 -n 0 -s "100 1500 100" -p 10 -f p1.pcap        
   - send with constant rate 500pps (bandwidth changes), increase length by 100 bytes every 5s from 100 to 150
     ./packETHcli -i eth1 -m 4 -d 2000 -n 0 -s "100 1500 100" -p 5 -f p1.pcap      
   - send with constant rate 500pps (bandwidth changes), increase length by 100 bytes every 5s from 100 to 150
     ./packETHcli -i eth1 -m 4 -B 10 -t 300 -s "1000 1500 100" -p 10 -f p1.pcap    

###  mode 5 - send packets for IDS testing:
   - send 50% IDS traffic (-a 2) at 10Mbit/s for 60 seconds, packet size 1000 bytes
     ./packETHcli -i eth1 -m 5 -f sample_snort_rules.txt -B 10 -t 60 -S1000 -a 2    
   - send 50% IDS traffic (-a 2) at 10Mbit/s for 60 seconds, packet size 1000 bytes
     ./packETHcli -i eth1 -m 5 -f sample_snort_rules.txt -d 1000 -t 60 -s "100 1000 100" -a 4 -p 10  
