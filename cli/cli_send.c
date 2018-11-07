/*
 * packETH - ethernet packet generator
 * By Miha Jemec <jemcek@gmail.com>
 * Copyright 2014 Miha Jemec
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 */


#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/time.h>

#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PCAP_MAGIC   0xa1b2c3d4
#ifndef MAX_MTU
    #define MAX_MTU 9000
    #define MAX_MTU_STR "9000"
#endif



/* "libpcap" file header (minus magic number). */
struct pcap_hdr {
    uint32_t     magic;          /* magic */
    uint16_t     version_major;  /* major version number */
    uint16_t     version_minor;  /* minor version number */
    uint32_t     thiszone;       /* GMT to local correction */
    uint32_t     sigfigs;        /* accuracy of timestamps */
    uint32_t     snaplen;        /* max length of captured packets, in octets */
    uint32_t     network;        /* data link type */
};

/* "libpcap" record header. */
struct pcaprec_hdr {
    int32_t      ts_sec;         /* timestamp seconds */
    uint32_t     ts_usec;        /* timestamp microseconds */
    uint32_t     incl_len;       /* number of octets of packet saved in file */
    uint32_t     orig_len;       /* actual length of packet */
};

struct params {
    struct sockaddr_ll sa;
    struct ifreq ifr;
    struct pcap_hdr fh;
    struct pcaprec_hdr ph;
    char iftext[20];
    int fd;
    char *ptr; 
    char pkt_temp[10000];
    char filename[200];
    int delay;
    int bw;
    int BW;
    long number;
    long duration;
    int period;
    int attack;
    char sizeramp[50];
    char rateramp[50];
    char rateRAMP[50];
    int packetsize;
    int seqnum;

} params1;


/* Link-layer type; */
//static unsigned long pcap_link_type = 1;   /* Default is DLT-EN10MB */

/* for mode 4, please change them accordingly */
#define MAC_DST_ADDR    {0x00, 0x04, 0x23, 0xB7, 0x29, 0xC4}
#define MAC_SRC_ADDR    {0x00, 0x04, 0x23, 0xB7, 0x21, 0xD8}
#define IP_SRC_ADDR     0x0A0A0A0A
#define IP_DST_ADDR     0x0B0B0B0B
#define TCP_SRC_PORT    htons(80)
#define TCP_DST_PORT    (MyRandom(seed)>>16)

extern char **g_content;
extern char *null_payload;
uint16_t TCPChecksum(uint16_t* buf1, int buf1len, uint16_t* buf2, int buf2len);
uint32_t MyRandom(uint64_t *seed);
__sum16 ip_fast_csum(const void *iph, unsigned int ihl);
char *build_packet(char *buffer, int pktsize, int tot_rules, int *rule_idx, uint64_t *seed, int attack);
int readSnortRules(const char *filename);
void cleanupRules(int);
int send_single_packet(void);
int send_constant_stream(void);
int send_variable_rate(void);
int send_variable_size(void);
int send_ids_mode(void);
int two(char *interface, long delay, long pkt2send, char *filename, char *sizetmp, int period, char *ratetmp);
int four(char *interface, long delay, long pkt2send, char *filename, char *sizetmp, int period, int attack);
void usage(void);
void examples(void);
void print_final(struct timeval first, long packets_sent, char *interface_name);
int interface_setup(void);
int read_packet_from_file(char *filename);


int main(int argc, char *argv[])
{
    
    int mode=1;
    int c;
    char *p;

    /* set default values */
    params1.delay = -2;
    params1.bw = -2;
    params1.BW = -2;
    params1.number = -2;
    params1.duration = -2;
    params1.sizeramp[0]='\0';
    params1.rateramp[0]='\0';
    params1.rateRAMP[0]='\0';
    params1.iftext[0]='\0';
    params1.period = -2;
    params1.attack = 4;
    params1.packetsize = -2;
    params1.seqnum = -2;

    /* Scan CLI parameters */
    while ((c = getopt(argc, argv, "hei:m:d:t:b:B:n:s:S:p:f:z:Z:a:c:")) != -1) {
        switch(c) {
            case 'a': {
                params1.attack = strtol(optarg, &p, 10);
                params1.attack = (params1.attack < 0 || params1.attack > 4) ? 4 : params1.attack;
                break;
            }
            case 'h': {
                usage(); 
                break;
            }
            case 'e': {
                examples();
                break;
            }
            case 'i': {
                strcpy(params1.iftext, optarg); 
                break;
            }
            case 'm': {
                mode = strtol(optarg, &p, 10);
                break;
            }
            case 'd': {
                params1.delay = strtol(optarg, &p, 10);
                break;
            }
            case 'b': {
                params1.bw = strtol(optarg, &p, 10);
                break;
            }
            case 'c': {
                params1.seqnum = strtol(optarg, &p, 10);
                break;
            }
            case 'B': {
                params1.BW = strtol(optarg, &p, 10);
                break;
            }
            case 'n': {
                params1.number = strtol(optarg, &p, 10);
                break;
            }
            case 't': {
                params1.duration = strtol(optarg, &p, 10);
                break;
            }
            case 'S': {
                params1.packetsize = strtol(optarg, &p, 10);
                break;
            }
            case 's': {
                strncpy(params1.sizeramp, optarg, 20);
                break;
            }
            case 'z': {
                strncpy(params1.rateramp, optarg, 50);
                break;
            }
            case 'Z': {
                strncpy(params1.rateRAMP, optarg, 50);
                break;
            }
            case 'p': {
                params1.period = strtol(optarg, &p, 10);
                break;
            }
            case 'f': {
                strncpy(params1.filename, optarg, 99);
                break;
            }
            default:
                usage();
        }
    }

    if ( (mode!=1) && (mode!=2) && (mode!=3) && (mode!=4) && (mode!=5)) {
        printf("\n Wrong mode option (-m mode). Allowed 1,2,3,4 or 5.\n\n");
        exit (7);
    }

    if (argc == 1) 
        usage();        

    /* set up the selected interface */
    interface_setup();
    /* read packet from file in modes 1-4 */
    if (mode < 5)
        read_packet_from_file(params1.filename);

    switch (mode) {
        case 1: {
            send_single_packet();
            break;
        }
        case 2: {
            send_constant_stream();
            break;
        }
        case 3: {
            send_variable_rate();
            break;
        }
        case 4: {
            send_variable_size();
            break;
        }
        case 5: {
            send_ids_mode();
            break;
        }
    }
    return 0;
}

void usage(void)
{
    printf("\nUsage: packETHcli -m <mode > -i <interface> -f <file> [options]\n");
    printf(" \n");
    printf("FOR EXAMPLES SEE: ./packETHcli -e \n\n");
    printf(" <mode>:\n");
    printf("    1   - SEND PACKET ONCE (default mode): send packet from the pcap file once \n");
    printf("          Optional parameter:\n");
    printf("               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)\n");
    printf("                              to see sequence numbers of packets inside pcap file: tcpdump -# -r filename\n");
    printf("          Example: packETHcli -i lo -f packet.pcap\n\n");
    printf("    2   - SEND PACKET CONTINUOUSLY WITH CONSTANT RATE: send (first) packet from pcap file at constant rate\n");
    printf("          Parameters:\n");
    printf("              Number of packets to send or duration in seconds (only one option possible)\n");
    printf("               -n <number, 0> - number of packets to send or 0 for infinite\n");
    printf("               -t <seconds> - seconds to transmit\n");
    printf("              Delay between packets or sendrate (only one option possible)\n");
    printf("               -d <us, 0, -1> - delay between packets in micro seconds; select 0 for maximum speed with counters; select -1 for max speed without counters)\n");
    printf("               -b <bandwidth> - desired sending rate in kbit/s\n");
    printf("               -B <bandwidth> - desired sending rate in Mbit/s\n");
    printf("          Optional parameter:\n");
    printf("               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)\n");
    printf("          Example: ./packETHcli -i eth0 -m 2 -B 100 -n 10000 -f p1.pcap \n\n");
    printf("    3   - SEND PACKET CONTINUOUSLY WITH VARIABLE RATE (SPEED RAMP):\n");
    printf("          Parameters:\n");
    printf("              Number of packets to send or duration in seconds (only one option possible)\n");
    printf("               -n <number, 0> - number of packets to send or 0 for infinite\n");
    printf("               -t <seconds> - seconds to transmit\n");
    printf("              Startrate, Stoprate, Steprate and Step duration (only one option possible):\n");
    printf("               -z \"<startrate stoprate steprate)\" in kbit/s \n");
    printf("               -Z \"<startrate stoprate steprate)\" in Mbit/s \n");
    printf("              Step duration:\n" );
    printf("               -p <seconds> - period between steps in seconds \n");
    printf("          Optional parameter:\n");
    printf("               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)\n");
    printf("          Example: ./packETHcli -i eth1 -m 3 -t 3600 -Z \"500 100 1\" -p 5 -f p1.pcap \n\n");
    printf("    4   - SEND PACKET CONTINUOUSLY WITH VARIABLE SIZE (SIZE RAMP)\n");
    printf("          Parameters:\n");
    printf("              Number of packets to send or duration in seconds (only one option possible)\n");
    printf("               -n <number, 0> - number of packets to send or 0 for infinite\n");
    printf("               -t <seconds> - seconds to transmit\n");
    printf("              Delay between packets or sendrate (only one option possible). Choose first option for constant pps and second one for constant bandwidth\n");
    printf("               -d <us, 0> - delay between packets in micro seconds; select 0 for maximum speed\n");
    printf("               -b <bandwidth> - desired sending rate in kbit/s\n");
    printf("               -B <bandwidth> - desired sending rate in Mbit/s\n");
    printf("              Startsize, Stopsize, Stepsize and Step duration number\n");
    printf("               -s \"<startsize stopsize stepsize>\" in bytes (please note that TCP&UDP checksums are not (yet :) ) recalculated!!!) \n");
    printf("               -p <seconds> - period between steps in seconds\n");
    printf("          Optional parameter:\n");
    printf("               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)\n");
    printf("          Example: ./packETHcli -i eth1 -m 4 -d 2000 -n 0 -s \"100 1500 100\" -p 5 -f p1.pcap\n\n");
    printf("    5   - SEND SEQUENCE OF PACKETS (IDS TEST MODE)\n");
    printf("          Parameters\n");
    printf("            -f <attack definitions file in Snort rule format> \n"); 
    printf("            -a <numbers from 0 to 4> - innocent traffic for 0, 25%% attack for 1, 50%% attack for 2, 75%% attack for 3, 100%% attack for 4> \n");
    printf("            -S <packet size in bytes OR -s \"<startsize stopsize stepsize>\" -p <step period>\n");
    printf("            -d <us, 0, -1> - delay between packets OR -b <bandwidth in kbit/s>  OR -B <bandwidth in Mbit/s\n");
    printf("            -n <number, 0> - number of packets to send (0 for infinite) OR -t <duration in seconds>\n");
    printf("           Example: ./packETHcli -i lo -f sample_snort_rules.txt -B 10 -m 5 -t 60 -S 1000 -a 2\n\n");
    printf(" -f <file> - file name where packet is stored in pcap format (or attack definitions file in Snort rule format in mode 5) \n");
    printf("                                                                                                     \n");
    printf("FOR EXAMPLES SEE: ./packETHcli -e \n");
    printf("\n\n");
    exit (8);
}

void examples(void) {
    printf("\n");
    printf("Examples:  \n");
    printf("\n");
    printf("All examples assume that we send on interface eth0 and that the packet is stored in file p1.pcap\n");
    printf("\n");
    printf("  mode 1 - send one packet and exit:\n");
    printf("   ./packETHcli -i eth0 -f p1.pcap                                               - send packet p1.pcap once on interface eth0\n");
    printf("   ./packETHcli -i eth0 -f p10.pcap -c 5                                         - send 5th packet from file p10.pcap\n");
    printf("\n");
    printf("  mode 2 - send packets at constant rate:\n");
    printf("   ./packETHcli -i eth0 -m 2 -d 0 -n 0 -f p1.pcap                                - send at max speed, infinite times, display counters every seconf\n");
    printf("   ./packETHcli -i eth0 -m 2 -d -1 -n 0 -f p1.pcap                               - send at max speed, infinite times, no counters\n");
    printf("   ./packETHcli -i eth0 -m 2 -d 1000 -n 300 -f p1.pcap                           - send 300 packets with 1000 us (1ms) between them\n");
    printf("   ./packETHcli -i eth0 -m 2 -b 1500 -t 30 -f p1.pcap                            - send packets with rate 1500 kbit/s for 30s\n");        
    printf("   ./packETHcli -i eth0 -m 2 -B 100 -n 10000 -f p1.pcap -c 7                     - send 7th packet 10000 times, with rate 100 Mbit/s\n");        
    printf("\n");
    printf("  mode 3 - send packets with different rates (speed ramp):\n");
    printf("   ./packETHcli -i eth1 -m   -n 0 -z \"100 1500 100\" -p 10 -f p1.pcap             - start sendind at 100kbit/s for 10s, then increase rate by 100kbit/s each 10s up to 1500 kbit/s\n");
    printf("   ./packETHcli -i eth1 -m 3 -t 3600 -Z \"500 100 1\" -p 5 -f p1.pcap              - send with 500Mbit/s for 5s, then decrease rate by 1Mbit/s each 5s. Stop after 3600s if not finished\n");
    printf("\n");
    printf("  mode 4 - send packets with variable size (size ramp):\n");
    printf("   ./packETHcli -i eth1 -m 4 -d 0 -n 0 -s \"100 1500 100\" -p 10 -f p1.pcap        - send at max speed, start with packet size of 100 bytes for 10s then increase by 100 bytes up to 1500 bytes\n");
    printf("   ./packETHcli -i eth1 -m 4 -d 2000 -n 0 -s \"100 1500 100\" -p 5 -f p1.pcap      - send with constant rate 500pps (bandwidth changes), increase length by 100 bytes every 5s from 100 to 1500 \n");
    printf("   ./packETHcli -i eth1 -m 4 -B 10 -t 300 -s \"1000 1500 100\" -p 10 -f p1.pcap    - send with constant bandwidth 10Mbit/s (pps changes), increase the length by 100 bytes every 10s from 1000 to 1500\n");
    printf("\n");
    printf("  mode 5 - send packets for IDS testing:\n");
    printf("   ./packETHcli -i eth1 -m 5 -f sample_snort_rules.txt -B 10 -t 60 -S1000 -a 2    - send 50%% IDS traffic (-a 2) at 10Mbit/s for 60 seconds, packet size 1000 bytes\n");
    printf("   ./packETHcli -i eth1 -m 5 -f sample_snort_rules.txt -d 1000 -t 60 -s \"100 1000 100\" -a 4 -p 10  - send 100%% IDS traffic, 1000pps for 60 seconds, increase packet size from 100 to 1000 bytes\n");
    printf("\n");
    printf("\n\n");
    exit (8);    
}


int send_single_packet(void)
{
    int c;

    if ((params1.delay != -2 ) || (params1.bw != -2) || (params1.BW != -2) || (params1.number != -2) || (params1.duration != -2) || (params1.packetsize != -2)) {
        printf("\n No options allowed in this mode! You can only select interface (-i) and filename (-f) and packet number (-c)!\n\n");
        return 1;
    }

    if ((strlen(params1.sizeramp) > 0) || (strlen(params1.rateramp) > 0 ) || (strlen(params1.rateRAMP) > 0 ) || (params1.period != -2)) {
        printf("\n No options allowed in this mode! You can only select interface (-i) and filename (-f)\n\n");
        return 1;
    }

    c = sendto(params1.fd, params1.ptr, params1.ph.incl_len, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));

    printf("\nThere were %d bytes sent on the interface %s\n\n", c, params1.iftext);
    fflush(stdout);

    exit(1);
}


/* send one packet more than once */
//int two(char *iftext, long delay, long pkt2send, char* filename, char *sizetmp, int period, char *ratetmp) {

int send_constant_stream() {

    int c;
   
    long li, gap = 0, gap2 = 0, sentnumber = 0, lastnumber = 0, seconds = 0;
    struct timeval nowstr, first, last;
    unsigned int mbps, pkts, link;
    float Mbps, Link;

    //check if the options are ok
    if ((params1.number == -2) && (params1.duration == -2)) {
        printf("\n Missing number of packets to send or time in seconds to transmit.\n Specify -n <number of packets> or -t <seconds to transmit>.\n");
        printf(" Set -n 0 to send infinite number of packets\n\n");
        exit(7);
    }
    else if ((params1.number != -2) && (params1.duration != -2)) {
        printf("\n Only one option allowed at a time (-n or -t). \n Specify -n <number of packets> or -t <seconds to tramsmit>!\n\n");
        exit(7);
    }
    else if ((params1.number != -2) && (params1.duration != -2)) {
        printf("\n Only one option allowed at a time (-n or -t). \n Specify -n <number of packets> or -t <seconds to tramsmit>!\n\n");
        exit(7);
    }
    if ((params1.delay == -2) && (params1.bw == -2) && (params1.BW == -2))  {
        printf("\n Missing delay between packets or desired bandwidth to send at. \n Specify -d <delay between packets in microseconds> or -b <bandwidth in kbits/s> or -B <bandwidth in Mbits/s>!\n\n");
        exit(7);
    }
    else if ( ((params1.delay != -2) && (params1.bw != -2)) || ((params1.delay != -2) && (params1.BW != -2)) || ((params1.bw != -2) && (params1.BW != -2)) ) {
        printf("\n Only one option allowed at a time (-d or -b or -B). \n Specify -d <delay between packets in microseconds> or -b <bandwidth in kbits/s> or -B <bandwidth in Mbits/s>!\n\n");
        exit(7);
    }

    if ((params1.delay == -2) && (params1.bw > 0)) {
        params1.delay = 1000 * params1.ph.incl_len * 8 / params1.bw;
    }
    else if ((params1.delay == -2) && (params1.BW > 0)) {
        params1.delay = params1.ph.incl_len * 8 / params1.BW;
    }
    if ((params1.number == -2) && (params1.duration > 0)) {
        params1.number = 0;
    }
    
    if (params1.packetsize != -2) {
        printf("\n Option -S not allowed in this mode\n\n");
        exit(7);    
    }

    if ((strlen(params1.sizeramp) > 0 ) || (strlen(params1.rateramp) > 0 ) || (strlen(params1.rateRAMP) > 0 ) || (params1.period != -2)) {
        printf("\n Ramp options not allowed in this mode\n\n");
        exit(7);
    }
    if (params1.delay > 999000) {
            printf ("\n Warning! Rate is below 1pps, statistics will be displayed only when a packet will be sent.\n\n"); 
    }
    
   
    /* this is the time we started */
    gettimeofday(&first, NULL);
    gettimeofday(&last, NULL);
    gettimeofday(&nowstr, NULL);

    /* to send first packet immedialtelly */
    //gap = params1.delay;
    gap = 0;

    /*-----------------------------------------------------------------------------------------------*/

    //if the -1 for delay was choosed, just send as fast as possible, no output, no counters, nothing
    if ((params1.delay==-1) && (params1.number==0)) {
        for(;;)
            c = sendto(params1.fd, params1.ptr, params1.ph.incl_len, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));
    }
    /* else if delay == 0 send as fast as possible with counters... */
    else if (params1.delay==0) {
        for(li = 0; params1.number == 0 ? 1 : li < params1.number; li++) {
            gettimeofday(&nowstr, NULL);
            gap2 = (nowstr.tv_sec*1000000 + nowstr.tv_usec) - (first.tv_sec*1000000 + first.tv_usec);
            c = sendto(params1.fd, params1.ptr, params1.ph.incl_len, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));
            last.tv_sec = nowstr.tv_sec;
            last.tv_usec = nowstr.tv_usec;

            if (c > 0)
                sentnumber++;
            /* every second display number of sent packets */
            if (gap2 > (seconds+1)*1000000) {
                pkts = sentnumber - lastnumber;
                mbps = pkts * params1.ph.incl_len / 125; // 8 bits per byte / 1024 for kbit
                Mbps = (float)mbps/1000;
                /* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
                link = pkts * (params1.ph.incl_len + 24) / 125;
                Link = (float)link/1000;
                lastnumber = sentnumber;

                printf("  Sent %ld packets on %s; %d bytes packet length; %d packets/s; %.3f Mbit/s data rate; %.3f Mbit/s link utilization\n", sentnumber, params1.iftext, params1.ph.incl_len, pkts, Mbps, Link);
                fflush(stdout);
                seconds++;
                //exit if time has elapsed
                if ((params1.duration > 0) && (seconds >= params1.duration))
                    break;
            }
        }
        print_final(first, sentnumber, params1.iftext);

    }
    /* with counters and delay between packets set */
    else {
        for(li = 0; params1.number == 0 ? 1 : li < params1.number; li++) {
            while (gap < params1.delay) {
                gettimeofday(&nowstr, NULL);
                gap = (nowstr.tv_sec*1000000 + nowstr.tv_usec) - (last.tv_sec*1000000 + last.tv_usec);
                gap2 = (nowstr.tv_sec*1000000 + nowstr.tv_usec) - (first.tv_sec*1000000 + first.tv_usec);
                //gap2 = (nowstr.tv_sec*1000000 + nowstr.tv_usec) - (first.tv_sec*1000000 + first.tv_usec);
                //gap2 = nowstr.tv_sec - first.tv_sec;
                //seconds = nowstr.tv_sec - first.tv_sec;
            }
            c = sendto(params1.fd, params1.ptr, params1.ph.incl_len, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));

            last.tv_sec = nowstr.tv_sec;
            last.tv_usec = nowstr.tv_usec;
            gap = 0;

            if (c > 0)
                sentnumber++;

            /* every second display number of sent packets */
            if (gap2 > (seconds+1)*1000000) {
                //printf("delay %ld, period2 %d, rate %d, steprate %d", delay, period2, rate, steprate);
                pkts = sentnumber - lastnumber;
                mbps = pkts * params1.ph.incl_len / 125; // 8 bits per byte / 1024 for kbit
                Mbps = (float)mbps/1000;
                /* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
                link = pkts * (params1.ph.incl_len + 24) / 125;
                Link = (float)link/1000;
                lastnumber = sentnumber;
                if (params1.delay < 999000)
                    printf("  Sent %ld packets on %s; %d bytes packet length; %d packets/s; %.3f Mbit/s data rate; %.3f Mbit/s link utilization\n", sentnumber, params1.iftext, params1.ph.incl_len, pkts, Mbps, Link);
                else
                    printf("  Sent %ld packets on %s; %d bytes packet length; rate <1 packets/s; -- kbit/s data rate; -- kbit/s link utilization\n", sentnumber, params1.iftext, params1.ph.incl_len);
                fflush(stdout);
                seconds++;
                //exit if time has elapsed
                if ((params1.duration > 0) && (seconds >= params1.duration))
                    break; 
            }
        }
        print_final(first, sentnumber, params1.iftext);
        return 1;
    }
    return 1;
}

int send_variable_rate() {


    int c,  count, flag = 0;
    int Mega = 0;
   
    long li, gap = 0, gap2 = 0, sentnumber = 0, lastnumber = 0, seconds = 0;
    //float gaps;
    struct timeval nowstr, first, last;
    unsigned int mbps, pkts, link;
    float Mbps, Link;
    int size, rate=0, period2=0;
    
    int wordcount = 0;
    int startrate = 0;
    int stoprate = 0;
    int steprate = 0;

    //char *ptr; 
    char *p;
   
    char tmp8[50];   
    char tmp7[20];
    char ch;

    //check if the options are ok
    if ((params1.delay != -2) || (params1.bw != -2)) {
        printf("\n Delay (-d) and bandwidth (-b) options not allowed in this mode. Rate is specified with -z or -Zoption!\n\n");
        exit(7);
    }

    if ((params1.number == -2) && (params1.duration == -2)) {
        printf("\n Missing number of packets to send or time in seconds to transmit.\n Specify -n <number of packets> or -t <seconds to transmit>.\n");
        printf(" Set -n 0 to send until the ramp finishes. \n\n");
        exit(7);
    }
    else if ((params1.number != -2) && (params1.duration != -2)) {
        printf("\n Only one option allowed at a time (-n or -t). \n Specify -n <number of packets> or -t <seconds to tramsmit>!\n\n");
        printf(" Set -n 0 to send until the ramp finishes. \n\n");
        exit(7);
    }
    if ((params1.number == -2) && (params1.duration > 0)) {
        params1.number = 0;
    }

    if (params1.packetsize != -2) {
        printf("\n Option -S not allowed in this mode\n\n");
        exit(7);    
    }

    if (strlen(params1.sizeramp) > 0 ) {
        printf("\n Option -s not allowed in this mode. Packet size can not be changed.\n\n");
        exit(7);
    }
    if (( strlen(params1.rateramp) == 0 ) && (strlen(params1.rateRAMP) == 0 )) {
        printf("\n Did you specify rate with -z option (in kbit/s) or -Z (in Mbit/s)? \n And don't forget the quotation marks! (for example: -z \"100 1000 200\")\n\n");
        exit(7);
    }
    if (( strlen(params1.rateramp) > 0 ) && (strlen(params1.rateRAMP) > 0 )) {
        printf("\n Only one option allowed at a time: -z (kbit/s) or -Z (Mbit/s)!\"\n\n");
        exit(7);
    }
    if (params1.period == -2) {
        printf("\n Did you specify duration of one step (in seconds) with -p option?\n\n");
        exit(7);
    }

    size = params1.ph.incl_len;

    if (strlen(params1.rateramp) > 0 ) {
        strncpy(tmp8, params1.rateramp, 50);
        Mega = 0;
    }
    else if (strlen(params1.rateRAMP) > 0) {
        strncpy(tmp8, params1.rateRAMP, 50);
        Mega = 1;
    }
    else {
        printf("\n Shouldn't be here...\n\n");
        exit(7);
    }


    for (count = 0; count <= strlen(tmp8); count ++){
        ch = tmp8[count];
        if((isblank(ch)) || (tmp8[count] == '\0')){ 
            strncpy(tmp7, &tmp8[flag],count-flag); 
            tmp7[count-flag]='\0';
            if (wordcount==0) 
                startrate = strtol(tmp7, &p, 10);
            else if (wordcount ==1)                     
                stoprate = strtol(tmp7, &p, 10);
            else if (wordcount ==2)                     
                steprate = strtol(tmp7, &p, 10);

                    wordcount += 1;
            flag = count;
        }
        
    }

    if (Mega == 1) {
        startrate = startrate * 1000;
        stoprate = stoprate * 1000;
        steprate = steprate * 1000;
    }

    //we allow also the decreasing ramp
    if (startrate > stoprate) {
        //printf("\nstartrate is greater than stoprate (or did you forget the quotation marks?)\n\n");
        //exit(7);
        steprate = 0 - steprate;
    }
    if ((startrate < 1) || (stoprate < 1)) {
        printf("\nstartrate and stoprate must be >= 1kbit/s\n\n");
        exit(7);
    }
    if ((stoprate > 100000000) || (stoprate > 100000000)) {
        printf("\nstartrate and stoprate must be <= 100Gbit/s\n\n");
        exit(7);
    }

    if (1000 * size * 8 / startrate > 999000) {
        printf ("startrate is to low (less than 1pps)\n\n");
        exit(7); 
    }
    if (1000 * size * 8 / stoprate > 999000) {
        printf ("stoprate is to low (less than 1pps)\n\n");
        exit(7); 
    }

    params1.delay = 1000 * size * 8 / startrate;
    rate = startrate;
    
    
    /* this is the time we started */
    gettimeofday(&first, NULL);
    gettimeofday(&last, NULL);
    gettimeofday(&nowstr, NULL);

    /* to send first packet immedialtelly */
    //gap = params1.delay;
    gap = 0;

    /*-----------------------------------------------------------------------------------------------*/

    /* with counters and delay set */
    for(li = 0; params1.number == 0 ? 1 : li < params1.number; li++) {
        while (gap < params1.delay) {
            gettimeofday(&nowstr, NULL);
            gap = (nowstr.tv_sec*1000000 + nowstr.tv_usec) - (last.tv_sec*1000000 + last.tv_usec);
            gap2 = (nowstr.tv_sec*1000000 + nowstr.tv_usec) - (first.tv_sec*1000000 + first.tv_usec);
            //gap2 = nowstr.tv_sec - first.tv_sec;
        }

        c = sendto(params1.fd, params1.ptr, params1.ph.incl_len, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));

        last.tv_sec = nowstr.tv_sec;
        last.tv_usec = nowstr.tv_usec;
        gap = 0;

        if (c > 0)
            sentnumber++;

        /* every second display number of sent packets */
        if (gap2 > (seconds+1)*1000000) {
            //printf("delay %ld, period2 %d, rate %d, steprate %d", delay, period2, rate, steprate);
            pkts = sentnumber - lastnumber;
            mbps = pkts * params1.ph.incl_len / 125; // 8 bits per byte / 1024 for kbit
            /* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
            link = pkts * (params1.ph.incl_len + 24) / 125;
            Mbps = (float)mbps/1000;
            Link = (float)link/1000;
            lastnumber = sentnumber;

            printf("  Sent %ld packets on %s; %d packet length; %d packets/s; %.3f Mbit/s data rate; %.3f Mbit/s link utilization\n", sentnumber, params1.iftext, size, pkts, Mbps, Link);
            fflush(stdout);
            seconds++;

            if (steprate != 0) {
                if ( (period2 > (params1.period-2)) && (params1.period>0) ) {
                    //printf("delay %d in pa rate %d\n", params1.delay, rate);
                    rate = rate + steprate;
                    if ((steprate > 0) && (rate > stoprate)) {
                        print_final(first, sentnumber, params1.iftext);
                    }
                    else if ((steprate < 0) && (rate < stoprate)) {
                        print_final(first, sentnumber, params1.iftext);
                    }
                    params1.delay = (long)(rate*1000) / (size*8);
                    params1.delay = 1000000 / params1.delay;
                    period2 = 0;
                    
                }
                else
                period2++;
            }
            if ((params1.duration > 0) && (seconds >= params1.duration))
                    break;
        }
    }
    print_final(first, sentnumber, params1.iftext);
    return 1;
    
}


int send_variable_size() {


    int c,  count, flag = 0;
    int ConstantRate = 0;

    long li, gap = 0, gap2 = 0, sentnumber = 0, lastnumber = 0, seconds = 0, rate=0;
    //float gaps;
    struct timeval nowstr, first, last;
    unsigned int mbps, pkts, link;
    float Mbps, Link;
    int size,period2=0;
    int startsize = 0;
    int stopsize = 0;
    int stepsize = 0 ;
    int wordcount = 0;
    
    //char *ptr; 
    char *p;
   
    char tmp7[20];
    char ch;

    //check if the options are ok
    if ((params1.delay == -2) && (params1.bw == -2) && (params1.BW == -2))  {
        printf("\n Missing delay between packets or desired bandwidth to send at. \n Specify -d <delay between packets in microseconds> or -b <bandwidth in kbits/s> or -B <bandwidth in Mbits/s>!\n\n");
        exit(7);
    }
    else if ( ((params1.delay != -2) && (params1.bw != -2)) || ((params1.delay != -2) && (params1.BW != -2)) || ((params1.bw != -2) && (params1.BW != -2)) ) {
        printf("\n Only one option allowed at a time (-d or -b or -B). \n Specify -d <delay between packets in microseconds> or -b <bandwidth in kbits/s> or -B <bandwidth in Mbits/s>!\n\n");
        exit(7);
    }
    
    if ((params1.number == -2) && (params1.duration == -2)) {
        printf("\n Missing number of packets to send or time in seconds to transmit.\n Specify -n <number of packets> or -t <seconds to transmit>.\n");
        printf(" Set -n 0 to send until the ramp finishes. \n\n");
        exit(7);
    }
    else if ((params1.number != -2) && (params1.duration != -2)) {
        printf("\n Only one option allowed at a time (-n or -t). \n Specify -n <number of packets> or -t <seconds to tramsmit>!\n\n");
        printf(" Set -n 0 to send until the ramp finishes. \n\n");
        exit(7);
    }
    
    
    
    if ((params1.number == -2) && (params1.duration > 0)) {
        params1.number = 0;
    }

    if (params1.packetsize != -2) {
        printf("\n Option -S not allowed in this mode\n\n");
        exit(7);    
    }

    if (strlen(params1.rateramp) > 0 ) {
        printf("\n Options -z and -Z are not allowed in this mode.\n\n");
        exit(7);
    }

    if (params1.delay > 999000) {
            printf ("\n Warning! Rate is below 1pps, statistics will be displayed only when a packet will be sent.\n\n"); 
    }

    if (strlen(params1.sizeramp) ==0 ) {
        printf("\n Did you specify size ramp values with -s option (in bytes)? \n And don't forget the quotation marks! (for example: -s \"100 1000 200\")\n\n");
        exit(7);
    }

    if (params1.period == -2) {
        printf("\n Did you specify duration of one step (in seconds) with -p option?\n\n");
        exit(7);
    }

    
    for (count = 0; count <= strlen(params1.sizeramp); count ++){
        ch = params1.sizeramp[count];
        if((isblank(ch)) || (params1.sizeramp[count] == '\0')){ 
            strncpy(tmp7, &params1.sizeramp[flag],count-flag); 
            tmp7[count-flag]='\0';
            if (wordcount==0) 
                startsize = strtol(tmp7, &p, 10);
            else if (wordcount ==1)                     
                stopsize = strtol(tmp7, &p, 10);
            else if (wordcount ==2)                     
                stepsize = strtol(tmp7, &p, 10);

            wordcount += 1;
            flag = count;
        }
        
        }
    if (startsize > stopsize) {
        printf("\nstartsize is greater than stopzize (or did you forget the quotation marks?)\n\n");
        return 1;
    }
    if (startsize < 60) {
        printf("\nstartsize must be >60\n\n");
        return 1;
    }
    if (stopsize > MAX_MTU) {
        printf("\nstopsize must be <" MAX_MTU_STR "\n\n");
        return 1;
    }
    if (params1.ph.incl_len < stopsize) {
        printf("\nPacket loaded from pcap file is shorter than stopsize!\n\n");
        return 1;   
    }

    size = startsize;

    if ((params1.delay == -2) && (params1.bw > 0)) {
        params1.delay = 1000 * size * 8 / params1.bw;
        ConstantRate = 0;
        rate = params1.bw;
    }
    else if ((params1.delay == -2) && (params1.BW > 0)) {
        params1.delay = size * 8 / params1.BW;
        ConstantRate = 0;
        rate = params1.BW*1000;
    }
    else
        ConstantRate = 1;
      
    //printf("startsize %d, stopsize %d, stepsize %d and packet length %d\n", startsize, stopsize, stepsize, params1.ph.incl_len);  
    
    /* this is the time we started */
    gettimeofday(&first, NULL);
    gettimeofday(&last, NULL);
    gettimeofday(&nowstr, NULL);

    gap = 0;

    /*-----------------------------------------------------------------------------------------------*/

    
    /* if delay == 0 and infinite packets, send as fast as possible with counters... */
    if (params1.delay==0) {
        for(li = 0; params1.number == 0 ? 1 : li < params1.number; li++) {
            gettimeofday(&nowstr, NULL);
            gap2 = nowstr.tv_sec - first.tv_sec;
            c = sendto(params1.fd, params1.ptr, size, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));
            last.tv_sec = nowstr.tv_sec;
            last.tv_usec = nowstr.tv_usec;

            if (c > 0)
                sentnumber++;
            /* every second display number of sent packets */
            if (gap2 > seconds) {
                pkts = sentnumber - lastnumber;
                mbps = pkts * size / 125; // 8 bits per byte / 1024 for kbit
                /* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
                link = pkts * (size + 24) / 125;
                Mbps = (float)mbps/1000;
                Link = (float)link/1000;
                lastnumber = sentnumber;

                printf("  Sent %ld packets on %s; %d packet length; %d packets/s; %.3f Mbit/s data rate; %.3f Mbit/s link utilization\n", sentnumber, params1.iftext, size, pkts, Mbps, Link);
                fflush(stdout);
                seconds++;

                if (stepsize > 0) {
                    if ( (period2 > (params1.period-2)) && (params1.period>0) ) {
                        size = size + stepsize;
                        if (size > stopsize) {
                            print_final(first, sentnumber, params1.iftext);
                            fflush(stdout);
                            return 1;
                        }
                        period2 = 0;
                    }
                    else
                        period2++;
                }
            }
            if ((params1.duration > 0) && (seconds >= params1.duration))
                break;
        }
        print_final(first, sentnumber, params1.iftext);
        return 1;
    }
    /* with counters and delay set */
    else {
        for(li = 0; params1.number == 0 ? 1 : li < params1.number; li++) {
            while (gap < params1.delay) {
                gettimeofday(&nowstr, NULL);
                gap = (nowstr.tv_sec*1000000 + nowstr.tv_usec) - (last.tv_sec*1000000 + last.tv_usec);
                gap2 = (nowstr.tv_sec*1000000 + nowstr.tv_usec) - (first.tv_sec*1000000 + first.tv_usec);
                //gap2 = nowstr.tv_sec - first.tv_sec;
            }

            c = sendto(params1.fd, params1.ptr, size, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));

            last.tv_sec = nowstr.tv_sec;
            last.tv_usec = nowstr.tv_usec;
            gap = 0;

            if (c > 0)
                sentnumber++;

            /* every second display number of sent packets */
            if (gap2 > (seconds+1)*1000000) {
                //printf("delay %ld, period2 %d, rate %d, steprate %d", delay, period2, rate, steprate);
                pkts = sentnumber - lastnumber;
                mbps = pkts * size / 125; // 8 bits per byte / 1024 for kbit
                /* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
                link = pkts * (size + 24) / 125;
                Mbps = (float)mbps/1000;
                Link = (float)link/1000;
                lastnumber = sentnumber;

                printf("  Sent %ld packets on %s; %d packet length; %d packets/s; %.3f Mbit/s data rate; %.3f Mbit/s link utilization\n", sentnumber, params1.iftext, size, pkts, Mbps, Link);
                fflush(stdout);
                seconds++;

                if (stepsize > 0) {
                    //printf("startsize %d, stopsize %d, stepsize %d and packet length %d\n", startsize, stopsize, stepsize, params1.ph.incl_len);
                    if ( (period2 > (params1.period-2)) && (params1.period>0) ) {
                        size = size + stepsize;
                        if (size > stopsize) {
                            print_final(first, sentnumber, params1.iftext);
                            //printf("  Sent %ld packets on %s \n", sentnumber, iftext);
                            //fflush(stdout);
                            return 1;
                        }
                        period2 = 0;
                    }
                    else
                        period2++;
                }
                //if we want to keep the rate the same, we need to change the delay
                if (ConstantRate == 0) {
                    params1.delay = (long)(rate*1000) / (size*8);
                    params1.delay = 1000000 / params1.delay;
                }
            }
            if ((params1.duration > 0) && (seconds >= params1.duration))
                break;
        }
        print_final(first, sentnumber, params1.iftext);
        return 1;
    }
    return 1;
}



/*------------------------------------------------------------------------------*/

//send the packet once, and that is...
int interface_setup()
{    

    if (strlen(params1.iftext) == 0 ) {
        printf("\n You need to specify output interface (-i interface_name)\n\n");
        exit (7);
    }

    /* do we have the rights to do that? */
    if (getuid() && geteuid()) {
        //printf("Sorry but need the su rights!\n");
        printf("\nSorry but need the su rights!\n\n");
        exit (7);
    }

    /* open socket in raw mode */
    params1.fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (params1.fd == -1) {
        //printf("Error: Could not open socket!\n");
        printf("\nError: Could not open socket!\n\n");
        exit(7);
    }

    /* which interface would you like to use? */
    memset(&params1.ifr, 0, sizeof(params1.ifr));
    strncpy (params1.ifr.ifr_name, params1.iftext, sizeof(params1.ifr.ifr_name) - 1);
    params1.ifr.ifr_name[sizeof(params1.ifr.ifr_name)-1] = '\0';

    /* does the interface exists? */
    if (ioctl(params1.fd, SIOCGIFINDEX, &params1.ifr) == -1) {
        printf("\nNo such interface: %s\n\n", params1.iftext);
        close(params1.fd);
        exit(7);
    }

    /* is the interface up? */
    ioctl(params1.fd, SIOCGIFFLAGS, &params1.ifr);
    if ( (params1.ifr.ifr_flags & IFF_UP) == 0) {
        printf("\nInterface %s is down\n\n", params1.iftext);
        close(params1.fd);
        exit(7);
    }

    /* just write in the structure again */
    ioctl(params1.fd, SIOCGIFINDEX, &params1.ifr);

    /* well we need this to work, don't ask me what is it about */
    memset(&params1.sa, 0, sizeof (params1.sa));
    params1.sa.sll_family    = AF_PACKET;
    params1.sa.sll_ifindex   = params1.ifr.ifr_ifindex;
    params1.sa.sll_protocol  = htons(ETH_P_ALL);

    return 1;   
}

/*------------------------------------------------------------------------------*/

int read_packet_from_file(char *filename) {

    FILE *file_p;
    int freads;
    //int last=0
    int i=0;
    //char *ptr2;

    if((file_p = fopen(filename, "r")) == NULL) {
        printf("\nCan not open file for reading. Did you specify pcap file with option -f ?\n\n");
        exit(7);
    }

    /* first we read the pcap file header */
    freads = fread(params1.pkt_temp, sizeof(params1.fh), 1, file_p);
    /* if EOF, exit */
    if (freads == 0) {
        printf("\nPcap file not correct?\n\n");
        exit(7);
    }

    memcpy(&params1.fh, params1.pkt_temp, 24);

    /* if magic number in NOK, exit */
    if (params1.fh.magic != PCAP_MAGIC) {
        printf("\nWrong pcap file format?\n\n");
        exit(7);
    }

    // we can select which packet we want to send
    if (params1.seqnum == -2)
        params1.seqnum = 1;
    for (i=0; i < params1.seqnum; i++) {
        /* next the  pcap packet header */
        freads = fread(params1.pkt_temp, sizeof(params1.ph), 1, file_p);
    
            /* if EOF, exit */
            if (freads == 0) {
                printf("\nPcap file not correct?\n\n");
                exit(7);
            }
    
            /* copy the 16 bytes into ph structure */
            memcpy(&params1.ph, params1.pkt_temp, 16);    
            params1.ptr = params1.pkt_temp + sizeof(params1.ph);
    
            /* and the packet itself, but only up to the capture length */
            freads = fread(params1.ptr, params1.ph.incl_len, 1, file_p);
    
            /* if EOF, exit */
            if (freads == 0) {
                printf("\nWrong sequence number? Or wrong pcap file format?\n\n");
                exit(7);
        }
    }
    fclose(file_p);

    return 1;
}

/*------------------------------------------------------------------------------*/

void print_final(struct timeval first, long packets_sent, char *interface_name)
{
    struct timeval now;
    long duration;
    float duration_s;

    gettimeofday(&now, NULL);
    duration = (now.tv_sec*1000000 + now.tv_usec) - (first.tv_sec*1000000 + first.tv_usec);
    duration_s = (float)duration/1000000;
    printf("------------------------------------------------\n");
    printf("  Sent %ld packets on %s in %f second(s). \n", packets_sent, interface_name, duration_s);
    printf("------------------------------------------------\n");
    fflush(stdout);
    exit(1);  
}

/*------------------------------------------------------------------------------*/

inline __sum16
ip_fast_csum(const void *iph, unsigned int ihl)
{
    unsigned int sum;
    
    asm("  movl (%1), %0\n"
        "  subl $4, %2\n"
        "  jbe 2f\n"
        "  addl 4(%1), %0\n"
        "  adcl 8(%1), %0\n"
        "  adcl 12(%1), %0\n"
        "1: adcl 16(%1), %0\n"
        "  lea 4(%1), %1\n"
        "  decl %2\n"
        "  jne      1b\n"
        "  adcl $0, %0\n"
        "  movl %0, %2\n"
        "  shrl $16, %0\n"
        "  addw %w2, %w0\n"
        "  adcl $0, %0\n"
        "  notl %0\n"
        "2:"
        /* Since the input registers which are loaded with iph and ih
           are modified, we must also specify them as outputs, or gcc
           will assume they contain their original values. */
        : "=r" (sum), "=r" (iph), "=r" (ihl)
        : "1" (iph), "2" (ihl)
        : "memory");
    return (__sum16)sum;
}
/*------------------------------------------------------------------------------*/
uint16_t
TCPChecksum(uint16_t* buf1, int buf1len, uint16_t* buf2, int buf2len)
{
    uint32_t sum = 0;
    uint16_t tmp = 0;
    
    assert(buf2 == NULL || buf1len % 2 == 0);
    
    while (buf1len > 1) {
        sum += *buf1++;
        buf1len -= 2;
    }
    
    /*  Add left-over byte, if any */
    if (buf1len > 0) {
        tmp = 0;
        *(uint8_t *) &tmp = *(uint8_t *) buf1;
        sum += tmp;
    }
    
    if (buf2) {
        while (buf2len > 1) {
            sum += *buf2++;
            buf2len -= 2;
        }
        
        /*  Add left-over byte, if any */
        if (buf2len > 0) {
            tmp = 0;
            *(uint8_t *) &tmp = *(uint8_t *) buf2;
            sum += tmp;
        }
    }
    
    /* fold 32-bit sum to 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    
    return (uint16_t)~sum;
}
/*------------------------------------------------------------------------------*/
inline uint32_t
MyRandom(uint64_t *seed)
{
    *seed = *seed * 1103515245 + 12345;
    return (uint32_t)(*seed >> 32); 
}
/*------------------------------------------------------------------------------*/
char *
build_packet(char *buffer, int pktsize, int tot_rules, int *rule_idx, uint64_t *seed, int attack)
{
    struct ether_header *ethh;
    struct iphdr *iph;
    struct tcphdr *tcph;
    uint16_t tot_len;
    static struct
    {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t len;
    } __attribute__ ((aligned (__WORDSIZE))) pseudo_header = {
        IP_SRC_ADDR, IP_DST_ADDR, 0, IPPROTO_TCP, 0,
    };
    static u_int8_t ether_dhost[ETH_ALEN] = MAC_DST_ADDR;
    static u_int8_t ether_shost[ETH_ALEN] = MAC_SRC_ADDR;
    static uint64_t attack_meter = 0;
    uint64_t attack_index;
    uint8_t attack_packet = 0;
    
    /* build ether header (14B) */
    ethh = (struct ether_header *)buffer;
    memcpy(ethh->ether_dhost, ether_dhost, ETH_ALEN);
    memcpy(ethh->ether_shost, ether_shost, ETH_ALEN);
    ethh->ether_type = htons(ETHERTYPE_IP);

    tot_len = pktsize - sizeof(struct ether_header);
    
    /* build ip header (20B) */
    iph = (struct iphdr *)(ethh + 1);
    memset(iph, 0, sizeof (struct iphdr));      
    iph->ihl = (unsigned int)(sizeof(struct iphdr)>>2);
    iph->version = 4;
    iph->ttl = 32;
    iph->protocol = IPPROTO_TCP;
    /* in nbo */
    iph->saddr = IP_SRC_ADDR;
    iph->daddr = IP_DST_ADDR;
    iph->tot_len = htons(tot_len);
    iph->check = ip_fast_csum(iph, iph->ihl);

    /* build tcp header (20B) */
    tcph = (struct tcphdr *)((char *)buffer + sizeof(struct ether_header) +
                 sizeof(struct iphdr));
    memset(tcph, 0, sizeof (struct tcphdr));    
    tcph->source = TCP_SRC_PORT;
    tcph->dest = TCP_DST_PORT;
    tcph->seq = MyRandom(seed);
    tcph->ack_seq = MyRandom(seed);
    tcph->doff = (sizeof(struct tcphdr)>>2);
    tcph->res1 = 0;
    tcph->res2 = 0;
    tcph->urg = 0;
    tcph->ack = 1;
    tcph->psh = 0;
    tcph->rst = 0;
    tcph->syn = 0;
    tcph->fin = 0;
    tcph->window = htons(5840);

    attack_index = attack_meter & (4 - 1);
    switch (attack) {
    case 0:
        memcpy((char *)buffer + sizeof(struct ether_header) +
               sizeof(struct iphdr) + sizeof(struct tcphdr),
               null_payload, tot_len + sizeof(struct ether_header));
        break;
    case 1:
        if (attack_index == 0) {
            memcpy((char *)buffer + sizeof(struct ether_header) +
                   sizeof(struct iphdr) + sizeof(struct tcphdr),
                   g_content[*rule_idx], tot_len + sizeof(struct ether_header));
            attack_packet = 1;
        }
        else
            memcpy((char *)buffer + sizeof(struct ether_header) +
                   sizeof(struct iphdr) + sizeof(struct tcphdr),
                   null_payload, tot_len + sizeof(struct ether_header));
        break;
    case 2:
        if (attack_index == 0 || attack_index == 2) {
            memcpy((char *)buffer + sizeof(struct ether_header) +
                   sizeof(struct iphdr) + sizeof(struct tcphdr),
                   g_content[*rule_idx], tot_len + sizeof(struct ether_header));
            attack_packet = 1;          
        }
        else
            memcpy((char *)buffer + sizeof(struct ether_header) +
                   sizeof(struct iphdr) + sizeof(struct tcphdr),
                   null_payload, tot_len + sizeof(struct ether_header));
        break;
    case 3:
        if (attack_index != 0) {
            memcpy((char *)buffer + sizeof(struct ether_header) +
                   sizeof(struct iphdr) + sizeof(struct tcphdr),
                   g_content[*rule_idx], tot_len + sizeof(struct ether_header));
            attack_packet = 1;
        }
        else
            memcpy((char *)buffer + sizeof(struct ether_header) +
                   sizeof(struct iphdr) + sizeof(struct tcphdr),
                   null_payload, tot_len + sizeof(struct ether_header));
        break;
    case 4:
        /* build payload */
        memcpy((char *)buffer + sizeof(struct ether_header) +
               sizeof(struct iphdr) + sizeof(struct tcphdr),
               g_content[*rule_idx], tot_len + sizeof(struct ether_header));
        attack_packet = 1;
        break;
    default:
        fprintf(stderr, "Control can never come here!\n");
        exit(EXIT_FAILURE);
    }

    /* update rule offset */
    if (attack_packet)
        *rule_idx = (*rule_idx + 1) % tot_rules;

    /* update checksum */
    tot_len -= sizeof(struct iphdr);
    pseudo_header.len = htons(tot_len);
    tcph->check = TCPChecksum((uint16_t *) &pseudo_header,
                  sizeof(pseudo_header), (uint16_t *)tcph,
                  tot_len);

    attack_meter++;
    
    return buffer;
}
/*------------------------------------------------------------------------------*/
/* IDS mode */

//int four(char *iftext, long delay, long pkt2send, char* filename, char *sizetmp, int period, int attack)
int send_ids_mode() 
{
    int c, count, flag=0;
    int ConstantRate = 0;
    
    long li, gap = 0, gap2 = 0, sentnumber = 0, lastnumber = 0, seconds = 0, rate=0;
    struct timeval nowstr, first, last;
    unsigned int mbps, pkts, link;
    float Mbps, Link;

    int size, period2 = 0;
    int startsize = 60;
    int stopsize = 1500;
    int stepsize = 10;
    int wordcount = 0;
    
    int num_rules, rules_idx = 0;
    char *p;
    char tmp7[10];
    char ch;
    uint64_t seed;
    
    //check if the options are ok
    if ((params1.delay == -2) && (params1.bw == -2) && (params1.BW == -2))  {
        printf("\n Missing delay between packets or desired bandwidth to send at. \n Specify -d <delay between packets in microseconds> or -b <bandwidth in kbits/s> or -B <bandwidth in Mbits/s>!\n\n");
        exit(7);
    }
    else if ( ((params1.delay != -2) && (params1.bw != -2)) || ((params1.delay != -2) && (params1.BW != -2)) || ((params1.bw != -2) && (params1.BW != -2)) ) {
        printf("\n Only one option allowed at a time (-d or -b or -B). \n Specify -d <delay between packets in microseconds> or -b <bandwidth in kbits/s> or -B <bandwidth in Mbits/s>!\n\n");
        exit(7);
    }
    
    if ((params1.number == -2) && (params1.duration == -2)) {
        printf("\n Missing number of packets to send or time in seconds to transmit.\n Specify -n <number of packets> or -t <seconds to transmit>.\n");
        printf(" Set -n 0 to send until the ramp finishes. \n\n");
        exit(7);
    }
    else if ((params1.number != -2) && (params1.duration != -2)) {
        printf("\n Only one option allowed at a time (-n or -t). \n Specify -n <number of packets> or -t <seconds to tramsmit>!\n\n");
        printf(" Set -n 0 to send until the ramp finishes. \n\n");
        exit(7);
    }
    
    if ((params1.number == -2) && (params1.duration > 0)) {
        params1.number = 0;
    }

    if (strlen(params1.rateramp) > 0 ) {
        printf("\n Options -z and -Z are not allowed in this mode.\n\n");
        exit(7);
    }

    if (params1.seqnum != -2 ) {
        printf("\n Option -c not allowed in this mode.\n\n");
        exit(7);
    }
    
    if (params1.delay > 999000) {
            printf ("\n Warning! Rate is below 1pps, statistics will be displayed only when a packet will be sent.\n\n"); 
    }

    if ((strlen(params1.sizeramp) ==0 ) && (params1.packetsize == -2)) {
        printf("\n Did you specify packet size with -S or size ramp values with -s option (in bytes)? \n And don't forget the quotation marks! (for example: -s \"100 1000 200\")\n\n");
        exit(7);
    }

    if ((strlen(params1.sizeramp) > 0) && (params1.period == -2)) {
        printf("\n Did you specify duration of one step (in seconds) with -p option?\n\n");
        exit(7);
    }


    /* read snort rule file */
    num_rules = readSnortRules(params1.filename);
    if (num_rules == 0) {
        /* if there are no rules, then die! */
        fprintf(stderr, "Rules file is empty!\n");
        exit(EXIT_FAILURE);
    }
    
    if (strlen(params1.sizeramp) > 0 ) {
        for (count = 0; count <= strlen(params1.sizeramp); count ++){
            ch = params1.sizeramp[count];
            if((isblank(ch)) || (params1.sizeramp[count] == '\0')){ 
                strncpy(tmp7, &params1.sizeramp[flag],count-flag); 
                tmp7[count-flag]='\0';
                if (wordcount==0) 
                    startsize = strtol(tmp7, &p, 10);
                else if (wordcount == 1)
                    stopsize = strtol(tmp7, &p, 10);
                else if (wordcount == 2)
                    stepsize = strtol(tmp7, &p, 10);
                
                        wordcount += 1;
                flag = count;
            }
            
        }
        if (startsize > stopsize) {
            printf("\nstartsize is greater than stopzize\n\n");
            close(params1.fd);
            cleanupRules(num_rules);
            return 1;
        }
        if (startsize < 60) {
            printf("\nstartsize must be >60\n\n");
            close(params1.fd);
            cleanupRules(num_rules);            
            return 1;
        }
        if (stopsize > MAX_MTU) {
            printf("\nstopsize must be <%d\n\n", MAX_MTU);
            close(params1.fd);
            cleanupRules(num_rules);            
            return 1;
        }
        size = startsize;
    }
    else
        size = params1.packetsize;

    if ((params1.delay == -2) && (params1.bw > 0)) {
        params1.delay = 1000 * size * 8 / params1.bw;
        ConstantRate = 0;
        rate = params1.bw;
    }
    else if ((params1.delay == -2) && (params1.BW > 0)) {
        params1.delay = size * 8 / params1.BW;
        ConstantRate = 0;
        rate = params1.BW*1000;
    }
    else
        ConstantRate = 1;
    

    /* this is the time we started */
    gettimeofday(&first, NULL);
    gettimeofday(&last, NULL);
    gettimeofday(&nowstr, NULL);
    
    /* generate seed for random number generator */
    seed = first.tv_usec;
    
    /* to send first packet immedialtelly */
    gap = 0;
    
    /* if delay == 0 and infinite packets, send as fast as possible with counters... */
    if (params1.delay==0) {
        for(li = 0; params1.number == 0 ? 1 : li < params1.number; li++) {
            gettimeofday(&nowstr, NULL);
            gap2 = nowstr.tv_sec - first.tv_sec;
            params1.ptr = build_packet(params1.pkt_temp, size, num_rules, &rules_idx, &seed, params1.attack);
            c = sendto(params1.fd, params1.ptr, size, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));
            last.tv_sec = nowstr.tv_sec;
            last.tv_usec = nowstr.tv_usec;
            
            if (c > 0)
                sentnumber++;
            /* every second display number of sent packets */
            if (gap2 > seconds) {
                pkts = sentnumber - lastnumber;
                mbps = pkts * size / 125; // 8 bits per byte / 1024 for kbit
                /* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
                link = pkts * (size + 24) / 125;
                Mbps = (float)mbps/1000;
                Link = (float)link/1000;
                lastnumber = sentnumber;

                printf("  Sent %ld packets on %s; %d packet length; %d packets/s; %.3f Mbit/s data rate; %.3f Mbit/s link utilization\n", sentnumber, params1.iftext, size, pkts, Mbps, Link);
                fflush(stdout);
                seconds++;

                if (stepsize > 0) {
                    if ( (period2 > (params1.period-2)) && (params1.period>0) ) {
                        size = size + stepsize;
                        if (size > stopsize) {
                            print_final(first, sentnumber, params1.iftext);
                            fflush(stdout);
                            close(params1.fd);
                            cleanupRules(num_rules);            
                            return 1;
                        }
                        period2 = 0;
                    }
                    else
                        period2++;
                }
            }
            if ((params1.duration > 0) && (seconds >= params1.duration))
                break;
        }
        print_final(first, sentnumber, params1.iftext);
        return 1;
    }
    
    else {
        for(li = 0; params1.number == 0 ? 1 : li < params1.number; li++) {
            while (gap < params1.delay) {
                gettimeofday(&nowstr, NULL);
                gap = (nowstr.tv_sec*1000000 + nowstr.tv_usec) - (last.tv_sec*1000000 + last.tv_usec);
                gap2 = nowstr.tv_sec - first.tv_sec;
            }

            params1.ptr = build_packet(params1.pkt_temp, size, num_rules, &rules_idx, &seed, params1.attack);
            c = sendto(params1.fd, params1.ptr, size, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));

            last.tv_sec = nowstr.tv_sec;
            last.tv_usec = nowstr.tv_usec;
            gap = 0;

            if (c > 0)
                sentnumber++;

            /* every second display number of sent packets */
            if (gap2 > seconds) {
                pkts = sentnumber - lastnumber;
                mbps = pkts * size / 125; // 8 bits per byte / 1024 for kbit
                /* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
                link = pkts * (size + 24) / 125;
                Mbps = (float)mbps/1000;
                Link = (float)link/1000;
                lastnumber = sentnumber;

                printf("  Sent %ld packets on %s; %d packet length; %d packets/s; %.3f Mbit/s data rate; %.3f Mbit/s link utilization\n", sentnumber, params1.iftext, size, pkts, Mbps, Link);
                fflush(stdout);
                seconds++;

                if (stepsize > 0) {
                    if ( (period2 > (params1.period-2)) && (params1.period>0) ) {
                        size = size + stepsize;
                        if (size > stopsize) {
                            print_final(first, sentnumber, params1.iftext);
                            close(params1.fd);
                            cleanupRules(num_rules);
                            return 1;
                        }
                        period2 = 0;
                    }
                    else
                        period2++;
                }
                //if we want to keep the rate the same, we need to change the delay
                if (ConstantRate == 0) {
                    params1.delay = (long)(rate*1000) / (size*8);
                    params1.delay = 1000000 / params1.delay;
                }
            }
            if ((params1.duration > 0) && (seconds >= params1.duration))
                break;
        }
        print_final(first, sentnumber, params1.iftext);
        close(params1.fd);
        cleanupRules(num_rules);        
        return 1;
    }

    close(params1.fd);
    cleanupRules(num_rules);
    return 1;
}


