/*
 * packETH, packETHcli - ethernet packet generator
 * By Miha Jemec <jemcek@gmail.com>
 * Copyright 2018 Miha Jemec
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
#include <signal.h>

#include <assert.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>

#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define PCAP_MAGIC   0xa1b2c3d4
#ifndef MAX_MTU
    #define MAX_MTU 9000
    #define MAX_MTU_STR "9000"
#endif

#define MY_PATTERN "a9b8c7d6"
//char my_pattern[]="a9b8c7d6";

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
    int mode;
    struct sockaddr_ll sa;
    struct ifreq ifr;
    struct ifreq ifopts;    /* set promiscuous mode */
    struct pcap_hdr fh;
    struct pcaprec_hdr ph;
    char iftext[20];
    int fd;
    char *ptr; 
    char pkt_temp[10000];
    char filename[200];
    long long delay;
    int bw;
    int BW;
    long long number;
    long duration;
    int period;
    int attack;
    char sizeramp[50];
    char rateramp[50];
    char rateRAMP[50];
    char burstargs[50];
    int packetsize;
    int seqnum;
    int offset_counter;
    int offset_pattern;
    char pattern[20];
    int my_pattern;
    int delay_mode;
    int paramnum;
    int display_interval;
    int rate;
    int size;
    int startrate;
    int stoprate;
    int steprate;
    int startsize;
    int stopsize;
    int stepsize;
    int ConstantRate;
    int num_rules;
    int burst_size;
    int burst_packets_in_burst;
    int burst_delay_between_packets;
    int burst_delay_to_next_burst;
    int burst_total;


} params1;

int STOP=0;

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
int send_burst_constant_mode(void);
int send_ids_mode(void);
int receiver_mode(void);
int two(char *interface, long delay, long pkt2send, char *filename, char *sizetmp, int period, char *ratetmp);
int four(char *interface, long delay, long pkt2send, char *filename, char *sizetmp, int period, int attack);
void usage(void);
void usage_1(void);
void usage_2(void);
void usage_3(void);
void usage_4(void);
void usage_5(void);
void usage_6(void);
void usage_9(void);
void examples(void);
void print_final(struct timeval first, long packets_sent, char *interface_name);
void print_intermidiate(long packets_sent, long packets_last_sent, int packet_size, int print_interval);
void onexit(int);
int interface_setup(void);
int read_packet_from_file(char *filename);
int function_send(void);
int function_send_burst(void);



int main(int argc, char *argv[])
{
    
    int c;
    char *p;

    /* set default values */
    params1.mode=1;
    params1.delay = -2;
    params1.bw = -2;
    params1.BW = -2;
    params1.number = -2;
    params1.duration = -2;
    params1.sizeramp[0]='\0';
    params1.rateramp[0]='\0';
    params1.rateRAMP[0]='\0';
    params1.burstargs[0]='\0';
    params1.iftext[0]='\0';
    params1.period = -2;
    params1.attack = -2;
    params1.packetsize = -2;
    params1.seqnum = -2;
    params1.pattern[0]='\0';
    params1.offset_counter = 0;
    params1.offset_pattern = 0;
    params1.my_pattern = 0;
    params1.delay_mode = 0;
    params1.paramnum = 0;
    params1.display_interval = 1;
    params1.rate = 0;
    params1.size = 0;
    params1.startrate = 0;
    params1.stoprate = 0;
    params1.steprate = 0;
    params1.startsize = 0;
    params1.stopsize = 0;
    params1.stepsize = 0 ;
    params1.ConstantRate = 0;
    params1.num_rules = 0;
    params1.burst_size = 0;
    params1.burst_packets_in_burst = 0;
    params1.burst_delay_between_packets = 0;
    params1.burst_delay_to_next_burst = 0;
    params1.burst_total = 0;

    setlinebuf(stdout);

    /* Scan CLI parameters */
    while ((c = getopt(argc, argv, "heI:i:m:d:D:t:b:B:n:s:S:L:p:f:z:Z:a:c:o:q:w:x")) != -1) {
        switch(c) {
            case 'a': {
                params1.attack = strtol(optarg, &p, 10);
                if ((params1.attack < 1) || (params1.attack > 4)) {
                   printf("\n Selected amount of attack traffic (-a <value>) should be between 1-4!\n\n");
                   exit(0);
                }
                params1.attack = (params1.attack < 0 || params1.attack > 4) ? 4 : params1.attack;
                break;
            }
            case 'h': {
                usage(); 
                usage_1(); 
                usage_2(); 
                usage_3(); 
                usage_4(); 
                usage_5(); 
                usage_6(); 
                usage_9();
                exit(0); 
                break;
            }
            case 'e': {
                examples();
                break;
            }
            case 'i': {
                strcpy(params1.iftext, optarg); 
                // waht values are allowed
                break;
            }
            case 'I': {
                params1.display_interval = strtol(optarg, &p, 10); 
                if ((params1.display_interval < 1) || (params1.display_interval > 600)) {
                   printf("\n Diplay interval (-I <value>) should be between 1s (default) and 600s!\n\n");
                   exit(0);
                }
                break;
            }
            case 'm': {
                params1.mode = strtol(optarg, &p, 10);
                if ( (params1.mode!=1) && (params1.mode!=2) && (params1.mode!=3) && (params1.mode!=4) && (params1.mode!=5) && (params1.mode!=6) && (params1.mode!=9)) {
                    printf("\n Wrong mode option (-m mode). Allowed 1,2,3,4,5,6 or 9.\n\n");
                    exit(0);
                }
                break;
            }
            case 'd': {
                params1.delay = strtoll(optarg, &p, 10);
                params1.delay_mode = params1.delay_mode + 1;
                if ( (params1.delay < -1) || (params1.delay > 100000000)) {
                    printf("\n Delay between packets (-d <value>) should be between 0 and 100000000ms (100s).\n\n");
                    exit(0);
                }
                break;
            }
            case 'D': {
                params1.delay = strtoll(optarg, &p, 10);
                params1.delay_mode = params1.delay_mode + 2;
                if ( (params1.delay < 1) || (params1.delay > 1000000000)) {
                    printf("\n Delay between packets (-D <value>) should be between 1 and 1000000000ns (1s).\n\n");
                    exit(0);
                }
                break;
            }
            case 'b': {
                params1.bw = strtol(optarg, &p, 10);
                params1.delay_mode = params1.delay_mode + 4;
                if ((params1.bw < 1) || (params1.bw > 100000000)) {
                    printf("\n Desired bandwidth  (-b <value>) should be between 1kbit/s and 100Gbit/s!\n\n");
                    exit(0);
                }
                break;
            }
            case 'B': {
                params1.BW = strtol(optarg, &p, 10);
                params1.delay_mode = params1.delay_mode + 8;
                if ((params1.BW < 1) || (params1.BW > 100000000)) {
                    printf("\n Desired bandwidth  (-B <value>) should be between 1Mbit/s and 100Gbit/s!\n\n");
                    exit(0);
                }
                break;
            }
            case 'c': {
                params1.seqnum = strtol(optarg, &p, 10);
                break;
            }
            case 'n': {
                params1.number = strtoll(optarg, &p, 10);
                if ((params1.number < 0) || (params1.number > 10000000000000000)) {
                    printf("\n Number of packets to send (-n <value>) out of range!\n\n");
                    exit(0);
                }
                break;
            }
            case 't': {
                params1.duration = strtol(optarg, &p, 10);
                if ((params1.duration < 1) || (params1.duration > 360000000)) {
                    printf("\n Duration (-t <value>) out of range!\n\n");
                    exit(0);
                }
                break;
            }
            case 'S': {
                params1.packetsize = strtol(optarg, &p, 10);
                if ((params1.packetsize < 60) || (params1.packetsize > MAX_MTU)) {
                    printf("\n Packetsize (-S <value>) out of range!\n\n");
                    exit(0);
                }
                break;
            }
            case 'L': {
                memcpy(params1.burstargs, optarg, 50);
                break;
            }
            case 's': {
                memcpy(params1.sizeramp, optarg, 20);
                break;
            }
            case 'z': {
                memcpy(params1.rateramp, optarg, 50);
                break;
            }
            case 'Z': {
                memcpy(params1.rateRAMP, optarg, 50);
                break;
            }
            case 'p': {
                params1.period = strtol(optarg, &p, 10);
                if ((params1.period < 1) || (params1.period > 360000)) {
                    printf("\n Period (-p <value>) out of range!\n\n");
                    exit(0);
                }
                break;
            }
            case 'o': {
                params1.offset_counter = strtol(optarg, &p, 10);
                params1.my_pattern = params1.my_pattern + 2;
                if ((params1.offset_counter < 1) || (params1.offset_counter > MAX_MTU)) {
                    printf("\n Offset counter (-o <value>) out of range!\n\n");
                    exit(0);
                }
                break;
            }
            case 'q': {
                params1.offset_pattern = strtol(optarg, &p, 10);
                params1.my_pattern = params1.my_pattern + 4;
                if ((params1.offset_pattern < 1) || (params1.offset_pattern > MAX_MTU)) {
                    printf("\n Offset pattern (-q <value>) out of range!\n\n");
                    exit(0);
                }
                break;
            }
            case 'w': {
                memcpy(params1.pattern, optarg, 20);
                params1.my_pattern = params1.my_pattern + 8;
                break;
            }
            case 'x': {
                params1.my_pattern = params1.my_pattern + 1;
                break;
            }
            case 'f': {
                memcpy(params1.filename, optarg, 99);
                break;
            }
            default: {
                usage();
                exit(0);
            }
        }
    }
   
    
    if (argc == 1) {
        usage();
        printf("FOR COMPLETE HELP: ./packETHcli -h\n");
        printf("\n");   
        exit(0);      
    }

    
    if (argc == 3) {
        //just the help
        params1.paramnum = 1;
    }
    else {
        /* set up the selected interface */
        interface_setup();
        /* read packet from file in modes 1-4 */
        if ((params1.mode < 5) || (params1.mode == 6))
            read_packet_from_file(params1.filename);
    }

    switch (params1.mode) {
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
        case 6: {
            send_burst_constant_mode();
            break;
        }
        case 9: {
            receiver_mode();
            break;
        }
    }
    return 0;
}


/*------------------------------------------------------------------------------*/
int receiver_mode(void) {

    char buf[10000];
    ssize_t recv_size = -1, size = 0;

    int firstround=0, first_packet=0;
    long packets=0, packets_total=0, my_packets=0, my_total_packets=0;
    long seconds=0, gap=0, errors=0; 
    //long gapns=0;
    unsigned int last_value=0, current_value=0;
    long mbps;
    float Mbps;

    //struct sockaddr_ll socket_address;
    //struct ifreq ifr;
    //char iftext[30];

    struct timeval nowstr, first;
    //struct timespec first_ns, now_ns;

    //char pattern[30];   
    //int offset_counter=0;
    //int offset_pattern=0;
    //int my_pattern=0;

    // print help for this mode
    if (params1.paramnum == 1) {  
        usage_9();
        exit(0);
    }

    if ((params1.my_pattern > 1) && (params1.my_pattern != 14)) {
        printf("\n Wrong pattern parameters. Choose one option:\n\n");
        printf("   Predifined pattern:  -x \n");
        printf("   Custom pattern:      -o <offset_counter> -q <offset_pattern> -w <pattern> \n\n");
        exit(0);
    }
    else if (( strlen(params1.pattern) > 0) && ((params1.offset_counter == 0) || (params1.offset_pattern == 0))) {
        printf("\n Option -w requires options -o and -q!\n\n");
        exit(0);
    }
    else if (( params1.offset_counter != 0) && ((strlen(params1.pattern) == 0) || (params1.offset_pattern == 0))) {
        printf("\n Option -o requires options -q and -w!\n\n");
        exit(0);
    }
    else if (( params1.offset_pattern != 0) && ((strlen(params1.pattern) == 0) || (params1.offset_counter == 0))) {
        printf("\n Option -q requires options -o and -w!\n\n");
        exit(0);
    }
    else if (strlen(params1.pattern) > 16) {
        printf("\n Pattern should not be longer than 16 chars!\n\n");
        exit(0);   
    }
    else if ((params1.offset_pattern < 0) || (params1.offset_pattern > 9900)) {
        printf("\n Offset of the pattern should be between 0 and 9900!\n\n");
        exit(0);   
    }
    else if ((params1.offset_counter < 0) || (params1.offset_counter > 9900)) {
        printf("\n Offset of the counter should be between 0 and 9900!\n\n");
        exit(0);   
    }
    else if ((strlen(params1.pattern) > 0) && (params1.offset_counter >= params1.offset_pattern) && (params1.offset_counter <= params1.offset_pattern + strlen(params1.pattern))) {
        printf("\n Counter position offset and pattern position offset should not overlap!\n\n");
        exit(0);   
    }
    else if (params1.attack != -2) {
        printf("\n -a option not allowed in this mode!\n\n");
        exit(0);      
    }
     if (params1.packetsize != -2) {
        printf("\n Option -S not allowed in this mode!\n\n");
        exit(0);    
    }
    if (params1.delay_mode != 0) {
        printf("\n Delay (-d, -D) and bandwidth (-b, -B) options not allowed in this mode!\n\n");
        exit(0);
    }
    if (params1.number != -2) {
        printf("\n Option (-n) not allowed in this mode!\n\n");
        exit(0);
    }
    if (params1.duration != -2) {
        printf("\n Option (-t) not allowed in this mode!\n\n");
        exit(0);
    }
    if (params1.display_interval != 1) {
        printf("\n Option (-I) ignored in this mode!\n\n");
        exit(0);
    }
    if ((strlen(params1.sizeramp) > 0 ) || (strlen(params1.rateramp) > 0 ) || (strlen(params1.rateRAMP) > 0 ) || (params1.period != -2)) {
        printf("\n Ramp options not allowed in this mode!\n\n");
        exit(0);
    }
    if (strlen(params1.filename) > 0) {
        printf("\n Option -f not allowed in this mode!\n\n");
        exit(0);
    }
    if (params1.seqnum != -2) {
        printf("\n Option -c not allowed in this mode!\n\n");
        exit(0);
    }

    signal(SIGINT, onexit);

    gettimeofday(&first, NULL);
    gettimeofday(&nowstr, NULL);

    while (1) {
        memset(&buf, 0, sizeof(buf));

        recv_size = recv(params1.fd, &buf, sizeof(buf), 0);

        //we received a packet
        if (recv_size > 0) {
            
            // is -x options enabled?
            if (params1.my_pattern == 1) {
                // do the last 10 bytes match
                if (strncmp(&buf[recv_size-10], MY_PATTERN, 8) == 0) {
                    //now check if the sequence number matches (this is the last byte in payload)
                    current_value = (unsigned int)buf[recv_size-1];
                    //printf("2 %02x %02x \n", current_value, last_value);        
                    
                    //if this is (re)start ignore the first packet value and don't count as error
                    if (first_packet == 0) {
                        first_packet = 1;
                    }
                    else if ((current_value != last_value + 1) && (current_value != last_value - 255)) {
                        //it doesn't match, so increase the error counter
                        errors++;
                    }

                    last_value = current_value; 
 
                    // ok they match, so this is my packet. We can increase the counter
                    my_packets++;
                    my_total_packets++;
                    size = recv_size;

                }

                // count all packets also not ours
                packets++;
                packets_total++;
                
            }
            // it seems that custom option was choosed
            else if (params1.offset_pattern > 0) {  
                // does the pattern matches?
                if (strncmp(&buf[params1.offset_pattern], params1.pattern, strlen(params1.pattern)) == 0) {
            
                    //now check if the sequence number matches (this is the last byte in payload)
                    current_value = (unsigned int)buf[params1.offset_counter-1];
                    //if this is (re)start ignore the first packet value and don't count as error
                    if (first_packet == 0) {
                        first_packet = 1;
                    }
                    else if ((current_value != last_value + 1) && (current_value != last_value - 255)) {
                        //it doesn't match, so increase the error counter
                        errors++;
                    }

                    last_value = current_value; 
 
                    // ok they match, so this is my packet. We can increase the counter
                    my_packets++;
                    my_total_packets++;
                    size = recv_size;
                   
                }

                packets++;
                packets_total++;
                
            }

            // we match all packets, so let's count them in case there is no filter
            else {
                packets++;
                packets_total++;
            }
            
            //printf("new packet\n");
            //for(i=0; i < recv_size; i++)
            //{
            //printf("%02x ", buf[i]);
            //}
            
            if (firstround == 0) {
                firstround = 1;
            }
 
        }


        gettimeofday(&nowstr, NULL);
        gap = nowstr.tv_sec - first.tv_sec;

        //clock_gettime(CLOCK_MONOTONIC, &now_ns);
        //gapns = now_ns.tv_sec - first_ns.tv_sec;
        
        //if (gapns > seconds) {
        if (gap > seconds) {
            if (firstround == 1) {
                firstround = 2;
                errors = 0;
            }
            else {
                mbps = my_packets * size / 125; // 8 bits per byte / 1024 for kbit
                Mbps = (float)mbps/1000;
                printf("Elapsed %lds; Interface %s; Matched packets: %ld pps, %.3f Mbit/s, total %ld packets, %ld sequence errors; All packets: %ld pps, total %ld \n", seconds, params1.iftext, my_packets, Mbps, my_total_packets, errors, packets, packets_total);
                
                // in case sender stops trasmitting and later restarts, we don't want to see this as an error
                if (my_packets == 0)
                    first_packet = 0;

                //some counters update
                seconds++;
                packets=0;
                my_packets=0;
            }

            if (STOP == 1)
                break;
        }
        
    }

    printf("----\n");
    printf("Received %ld my packets and %ld all packets on inteface %s\n", my_total_packets, packets_total, params1.iftext);
    printf("----\n");

    return 0;
}

/*------------------------------------------------------------------------------*/

int send_single_packet(void)
{
    int c;

    if (params1.paramnum == 1) {  
        usage_1();
        exit(0);
    }

    if ((params1.delay != -2 ) || (params1.bw != -2) || (params1.BW != -2) || (params1.number != -2) || (params1.duration != -2) || (params1.packetsize != -2) || (params1.attack != -2)) {
        printf("\n No special options allowed in this mode! You can only select interface (-i), filename (-f) and packet number (-c)!\n\n");
        return 1;
    }

    if ((strlen(params1.sizeramp) > 0) || (strlen(params1.rateramp) > 0 ) || (strlen(params1.rateRAMP) > 0 ) || (params1.period != -2) || (params1.my_pattern > 0)) {
        printf("\n No special options allowed in this mode! You can only select interface (-i), filename (-f) and packet number (-c)\n\n");
        return 1;
    }

    c = sendto(params1.fd, params1.ptr, params1.ph.incl_len, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));

    if (c > 0) {
        printf("\nSent 1 packet (%d bytes) on interface %s\n\n", c, params1.iftext);
        fflush(stdout);
        exit(0);
    }
    else {
        printf("\nProblems sending packet on interface: %s\n", params1.iftext);
        printf("Is interface up?\n");
        printf("Is MTU setting on interface large enough?\n\n");
        fflush(stdout);
        exit(1);
    }
}

/*------------------------------------------------------------------------------*/
/* send one packet more than once */
int send_constant_stream() {

    // print help for this mode
    if (params1.paramnum == 1) {  
        usage_2();
        exit(0);
    }

    //check if the options are ok
    if ((params1.number == -2) && (params1.duration == -2)) {
        printf("\n Missing number of packets to send or time in seconds to transmit.\n Specify -n <number of packets> or -t <seconds to transmit>.\n");
        printf(" Set -n 0 to send infinite number of packets\n\n");
        exit(0);
    }
    else if ((params1.number != -2) && (params1.duration != -2)) {
        printf("\n Only one option allowed at a time (-n or -t). \n Specify -n <number of packets> or -t <seconds to tramsmit>!\n\n");
        exit(0);
    }
    
    if ((params1.delay_mode != 1) && (params1.delay_mode != 2) && (params1.delay_mode != 4) && (params1.delay_mode != 8)) {
        printf("\n Wrong or missing delay between packets or bandwidth parameter.\n\n Specify one of the following options:\n");
        printf("   -D <nanoseconds>    - delay between packets in nanoseconds\n");
        printf("   -d <microseconds>   - delay between packets in microseconds\n");
        printf("   -d -1               - maximum speed without counters\n");
        printf("   -d 0                - maximum speed with counters\n");
        printf("   -b <bandwidth>      - desired bandwidth in kbit/s\n");
        printf("   -B <bandwidth>      - desired bandwidth in Mbit/s\n\n");
        exit(0);    
    }

    if (params1.delay_mode == 1)
        params1.delay = params1.delay * 1000;
    else if (params1.delay_mode == 2) 
        params1.delay = params1.delay;
    else if (params1.delay_mode == 4)
        params1.delay = (long long)(1000000 * (long long)params1.ph.incl_len * 8 / params1.bw);
    else if (params1.delay_mode == 8) 
        params1.delay = (long long)(1000 * (long long)params1.ph.incl_len * 8 / params1.BW);


    if ((params1.delay == -1000) && (params1.number != 0)) {
        printf("\n Option -d -1 also requires option -n 0 (infinite numbers of packest to send)\n\n");
        exit(0);
    }

    if ((params1.number == -2) && (params1.duration > 0)) {
        params1.number = 0;
    }
    
    if (params1.packetsize != -2) {
        printf("\n Option -S not allowed in this mode\n\n");
        exit(0);    
    }

    if ((strlen(params1.sizeramp) > 0 ) || (strlen(params1.rateramp) > 0 ) || (strlen(params1.rateRAMP) > 0 ) || (params1.period != -2)) {
        printf("\n Ramp options not allowed in this mode\n\n");
        exit(0);
    }
    if (params1.delay > 999000000) {
            printf ("\n Warning! Rate is below 1pps, statistics will be displayed only when a packet will be sent.\n\n"); 
    }
    if ((params1.my_pattern > 1) && (params1.my_pattern != 14)) {
        printf("\n Wrong pattern parameters. Choose one option:\n\n");
        printf("   Predifined pattern:  -x \n");
        printf("   Custom pattern:      -o <offset_counter> -q <offset_pattern> -w <pattern> \n\n");
        exit(0);
    }
    else if (strlen(params1.pattern) > 16) {
        printf("\n Pattern should not be longer than 16 chars!\n\n");
        exit(0);   
    }
    else if ((params1.offset_pattern < 0) || (params1.offset_pattern+strlen(params1.pattern) > params1.ph.incl_len)) {
        printf("\n Offset of the pattern is outside the packet size!\n\n");
        exit(0);   
    }
    else if ((params1.offset_counter < 0) || (params1.offset_counter > params1.ph.incl_len)) {
        printf("\n Offset of the counter is outside the packet size!\n\n");
        exit(0);   
    }
    else if ((params1.my_pattern > 1) && (params1.offset_counter >= params1.offset_pattern) && (params1.offset_counter <= params1.offset_pattern + strlen(params1.pattern))) {
        printf("\n Counter position and pattern position should not overlap!\n\n");
        exit(0);   
    }
    else if ((params1.delay == -1) && ((params1.offset_counter !=0) || (params1.offset_pattern != 0) || (strlen(params1.pattern) >0 ))) {
        printf("\n Option -x OR -o -q -w are not compatible with high speed -d -1 mode!\n\n");
        exit(0);   
    }
    if (params1.attack != -2) {
        printf("\n -a option not allowed in this mode!\n\n");
        exit(0);      
    }


    // if we insert my_pattern, this will be inserted from last 10 to last 2 bytes. Last 2 bytes themselves are reserved for counter 
    if (params1.my_pattern == 1) {
        memcpy(params1.ptr+params1.ph.incl_len-10, MY_PATTERN, 8);
        memset(params1.ptr+params1.ph.incl_len-2, 0, 1);
        memset(params1.ptr+params1.ph.incl_len-1, 1, 1);
    }

    // in case we use custom pattern and offset
    if(params1.my_pattern > 1) {
        memcpy(params1.ptr+params1.offset_pattern, params1.pattern, strlen(params1.pattern));
    }

    params1.size = params1.ph.incl_len; 

    //everything is set up, lets start sending
    function_send();

    return 1;
}

/*------------------------------------------------------------------------------*/
int send_variable_rate() {

    int count, flag = 0;
    int Mega = 0;

    int wordcount = 0;
    
    //char *ptr; 
    char *p;
   
    char tmp8[50];   
    char tmp7[20];
    char ch;

    if (params1.paramnum == 1) {  
        usage_3();
        exit(0);
    }

    //check if the options are ok
    if (params1.delay_mode != 0) {
        printf("\n Delay (-d, -D) and bandwidth (-b, -B) options not allowed in this mode. Rate is specified with -z or -Zoption!\n\n");
        exit(0);
    }

    if ((params1.number == -2) && (params1.duration == -2)) {
        printf("\n Missing number of packets to send or time in seconds to transmit.\n Specify -n <number of packets> or -t <seconds to transmit>.\n");
        printf(" Set -n 0 to send until the ramp finishes. \n\n");
        exit(0);
    }
    else if ((params1.number != -2) && (params1.duration != -2)) {
        printf("\n Only one option allowed at a time (-n or -t). \n Specify -n <number of packets> or -t <seconds to tramsmit>!\n\n");
        printf(" Set -n 0 to send until the ramp finishes. \n\n");
        exit(0);
    }
    if ((params1.number == -2) && (params1.duration > 0)) {
        params1.number = 0;
    }

    if (params1.packetsize != -2) {
        printf("\n Option -S not allowed in this mode\n\n");
        exit(0);    
    }
    if (params1.attack != -2) {
        printf("\n -a option not allowed in this mode!\n\n");
        exit(0);      
    }

    if (strlen(params1.sizeramp) > 0 ) {
        printf("\n Option -s not allowed in this mode. Packet size can not be changed.\n\n");
        exit(0);
    }
    if (( strlen(params1.rateramp) == 0 ) && (strlen(params1.rateRAMP) == 0 )) {
        printf("\n Did you specify rate with -z option (in kbit/s) or -Z (in Mbit/s)? \n And don't forget the quotation marks! (for example: -z \"100 1000 200\")\n\n");
        exit(0);
    }
    if (( strlen(params1.rateramp) > 0 ) && (strlen(params1.rateRAMP) > 0 )) {
        printf("\n Only one option allowed at a time: -z (kbit/s) or -Z (Mbit/s)!\"\n\n");
        exit(0);
    }
    if (params1.period == -2) {
        printf("\n Did you specify duration of one step (in seconds) with -p option?\n\n");
        exit(0);
    }

    if ((params1.my_pattern > 1) && (params1.my_pattern != 14)) {
        printf("\n Wrong pattern parameters. Choose one option:\n\n");
        printf("   Predifined pattern:  -x \n");
        printf("   Custom pattern:      -o <offset_counter> -q <offset_pattern> -w <pattern> \n\n");
        exit(0);
    }
    else if (strlen(params1.pattern) > 16) {
        printf("\n Pattern should not be longer than 16 chars!\n\n");
        exit(0);   
    }
    else if ((params1.offset_pattern < 0) || (params1.offset_pattern+strlen(params1.pattern) > params1.ph.incl_len)) {
        printf("\n Offset of the pattern is outside the packet size!\n\n");
        exit(0);   
    }
    else if ((params1.offset_counter < 0) || (params1.offset_counter > params1.ph.incl_len)) {
        printf("\n Offset of the counter is outside the packet size!\n\n");
        exit(0);   
    }
    else if ((params1.my_pattern > 1) && (params1.offset_counter >= params1.offset_pattern) && (params1.offset_counter <= params1.offset_pattern + strlen(params1.pattern))) {
        printf("\n Counter position and pattern position should not overlap!\n\n");
        exit(0);   
    }

    params1.size = params1.ph.incl_len;

    if (strlen(params1.rateramp) > 0 ) {
        memcpy(tmp8, params1.rateramp, 50);
        Mega = 0;
    }
    else if (strlen(params1.rateRAMP) > 0) {
        memcpy(tmp8, params1.rateRAMP, 50);
        Mega = 1;
    }
    else {
        printf("\n Shouldn't be here...\n\n");
        exit(0);
    }


    for (count = 0; count <= strlen(tmp8); count ++){
        ch = tmp8[count];
        if((isblank(ch)) || (tmp8[count] == '\0')){ 
            memcpy(tmp7, &tmp8[flag],count-flag); 
            tmp7[count-flag]='\0';
            if (wordcount==0) 
                params1.startrate = strtol(tmp7, &p, 10);
            else if (wordcount ==1)                     
                params1.stoprate = strtol(tmp7, &p, 10);
            else if (wordcount ==2)                     
                params1.steprate = strtol(tmp7, &p, 10);

                    wordcount += 1;
            flag = count;
        }
        
    }

    if (Mega == 1) {
        params1.startrate = params1.startrate * 1000;
        params1.stoprate = params1.stoprate * 1000;
        params1.steprate = params1.steprate * 1000;
    }

    //we allow also the decreasing ramp
    if (params1.startrate > params1.stoprate) {
        //printf("\nstartrate is greater than stoprate (or did you forget the quotation marks?)\n\n");
        //exit(0);
        params1.steprate = 0 - params1.steprate;
    }
    if ((params1.startrate < 1) || (params1.stoprate < 1)) {
        printf("\nstartrate and stoprate must be >= 1kbit/s\n\n");
        exit(0);
    }
    if ((params1.stoprate > 100000000) || (params1.stoprate > 100000000)) {
        printf("\nstartrate and stoprate must be <= 100Gbit/s\n\n");
        exit(0);
    }

    if (1000 * params1.size * 8 / params1.startrate > 999000) {
        printf ("startrate is to low (less than 1pps)\n\n");
        exit(0); 
    }
    if (1000 * params1.size * 8 / params1.stoprate > 999000) {
        printf ("stoprate is to low (less than 1pps)\n\n");
        exit(0); 
    }

    params1.delay = (long long)(1000000 * (long long)params1.size * 8 / params1.startrate);
    params1.rate = params1.startrate;
    
    
    // if we inser my_pattern, this will be inserted from last 10 to last 2 bytes. Last 2 bytes themselves are reserved for counter 
    if (params1.my_pattern == 1) {
        memcpy(params1.ptr+params1.ph.incl_len-10, MY_PATTERN, 8);
        memset(params1.ptr+params1.ph.incl_len-2, 0, 1);
        memset(params1.ptr+params1.ph.incl_len-1, 1, 1);
    }

    // in case we use custom pattern and offset
    if(params1.my_pattern > 1) {
        memcpy(params1.ptr+params1.offset_pattern, params1.pattern, strlen(params1.pattern));
    }
   
    function_send();
    return 1;
}

/*------------------------------------------------------------------------------*/
int send_variable_size() {

    int count, flag = 0;
    int wordcount = 0;
    char *p;
    char tmp7[20];
    char ch;

    if (params1.paramnum == 1) {  
        usage_4();
        exit(0);
    }

    //check if the options are ok
    if ((params1.delay_mode != 1) && (params1.delay_mode != 2) && (params1.delay_mode != 4) && (params1.delay_mode != 8)) {
        printf("\n Wrong or missing delay between packets or bandwidth parameter.\n\n Specify one of the following options:\n");
        printf("   -D <nanoseconds>    - delay between packets in nanoseconds\n");
        printf("   -d <microseconds>   - delay between packets in microseconds\n");
        printf("   -d 0                - maximum speed with counters\n");
        printf("   -b <bandwidth>      - desired bandwidth in kbit/s\n");
        printf("   -B <bandwidth>      - desired bandwidth in Mbit/s\n\n");
        exit(0);    
    }
    else if ((params1.delay_mode == 1) && (params1.delay == -1)) {
        printf("\n Option -d -1 not allowed with this mode\n\n");
        exit(0);
    }
    
    if (params1.delay_mode == 1)
        params1.delay = params1.delay * 1000;
    else if (params1.delay_mode == 2) 
        params1.delay = params1.delay;
    else if (params1.delay_mode == 4)
        params1.delay = (long long)(1000000 * (long long)params1.ph.incl_len * 8 / params1.bw);
    else if (params1.delay_mode == 8) 
        params1.delay = (long long)(1000 * (long long)params1.ph.incl_len * 8 / params1.BW);

    if (params1.delay > 999000000) {
            printf ("\n Warning! Rate is below 1pps, statistics will be displayed only when a packet will be sent.\n\n"); 
    }
    
    if ((params1.number == -2) && (params1.duration == -2)) {
        printf("\n Missing number of packets to send or time in seconds to transmit.\n Specify -n <number of packets> or -t <seconds to transmit>.\n");
        printf(" Set -n 0 to send until the ramp finishes. \n\n");
        exit(0);
    }
    else if ((params1.number != -2) && (params1.duration != -2)) {
        printf("\n Only one option allowed at a time (-n or -t). \n Specify -n <number of packets> or -t <seconds to tramsmit>!\n\n");
        printf(" Set -n 0 to send until the ramp finishes. \n\n");
        exit(0);
    } 
    
    if ((params1.number == -2) && (params1.duration > 0)) {
        params1.number = 0;
    }

    if (params1.packetsize != -2) {
        printf("\n Option -S not allowed in this mode\n\n");
        exit(0);    
    }
    if (params1.attack != -2) {
        printf("\n -a option not allowed in this mode!\n\n");
        exit(0);      
    }
    if (strlen(params1.rateramp) > 0 ) {
        printf("\n Options -z and -Z are not allowed in this mode.\n\n");
        exit(0);
    }

    if (strlen(params1.sizeramp) ==0 ) {
        printf("\n Did you specify size ramp values with -s option (in bytes)? \n And don't forget the quotation marks! (for example: -s \"100 1000 200\")\n\n");
        exit(0);
    }

    if (params1.period == -2) {
        printf("\n Did you specify duration of one step (in seconds) with -p option?\n\n");
        exit(0);
    }

    for (count = 0; count <= strlen(params1.sizeramp); count ++){
        ch = params1.sizeramp[count];
        if((isblank(ch)) || (params1.sizeramp[count] == '\0')){ 
            memcpy(tmp7, &params1.sizeramp[flag],count-flag); 
            tmp7[count-flag]='\0';
            if (wordcount==0) 
                params1.startsize = strtol(tmp7, &p, 10);
            else if (wordcount ==1)                     
                params1.stopsize = strtol(tmp7, &p, 10);
            else if (wordcount ==2)                     
                params1.stepsize = strtol(tmp7, &p, 10);

            wordcount += 1;
            flag = count;
        }
        
        }
    if (params1.startsize > params1.stopsize) {
        printf("\nstartsize is greater than stopzize (or did you forget the quotation marks?)\n\n");
        return 1;
    }
    if (params1.startsize < 60) {
        printf("\nstartsize must be >60\n\n");
        return 1;
    }
    if (params1.stopsize > MAX_MTU) {
        printf("\nstopsize must be <" MAX_MTU_STR "\n\n");
        return 1;
    }
    if (params1.ph.incl_len < params1.stopsize) {
        printf("\nPacket loaded from pcap file is shorter than stopsize!\n\n");
        return 1;   
    }

    if ((params1.my_pattern > 1) && (params1.my_pattern != 14)) {
        printf("\n Wrong pattern parameters. Choose one option:\n\n");
        printf("   Predifined pattern:  -x \n");
        printf("   Custom pattern:      -o <offset_counter> -q <offset_pattern> -w <pattern> \n\n");
        exit(0);
    }
    else if (strlen(params1.pattern) > 16) {
        printf("\n Pattern should not be longer than 16 chars!\n\n");
        exit(0);   
    }
    else if ((params1.offset_pattern < 0) || (params1.offset_pattern+strlen(params1.pattern) > params1.startsize)) {
        printf("\n Offset of the pattern is outside of the start packet size!\n\n");
        exit(0);   
    }
    else if ((params1.offset_counter < 0) || (params1.offset_counter > params1.startsize)) {
        printf("\n Offset of the counter is outside the start packet size!\n\n");
        exit(0);   
    }
    else if ((params1.my_pattern > 1) && (params1.offset_counter >= params1.offset_pattern) && (params1.offset_counter <= params1.offset_pattern + strlen(params1.pattern))) {
        printf("\n Counter position and pattern position should not overlap!\n\n");
        exit(0);   
    }

    params1.size = params1.startsize;

    if (params1.delay_mode == 4) {
        params1.delay = (long long)(1000000 * (long long)params1.size * 8 / params1.bw);
        params1.ConstantRate = 1;
        params1.rate = params1.bw;
    }
    else if (params1.delay_mode == 8) {
        params1.delay = (long long)(1000 * (long long)params1.size * 8 / params1.BW);
        params1.ConstantRate = 1;
        params1.rate = params1.BW*1000;
    }
    else
        params1.ConstantRate = 0;

    // if we inser my_pattern, this will be inserted from last 10 to last 2 bytes. Last 2 bytes themselves are reserved for counter 
    if (params1.my_pattern == 1) {
        memcpy(params1.ptr+params1.size-10, MY_PATTERN, 8);
        memset(params1.ptr+params1.size-2, 0, 1);
        memset(params1.ptr+params1.size-1, 1, 1);
    }

    // in case we use custom pattern and offset
    if(params1.my_pattern > 1) {
        memcpy(params1.ptr+params1.offset_pattern, params1.pattern, strlen(params1.pattern));
    }
    function_send();
    return 1;
}
 
/*------------------------------------------------------------------------------*/
int send_burst_constant_mode() {

    int count, flag = 0;
    int wordcount = 0;
    char *p;
    char tmp7[20];
    char ch;

    if (params1.paramnum == 1) {  
        usage_6();
        exit(0);
    }

    //check if the options are ok
    if (params1.delay_mode != 0) {
        printf("\n Option -d not allowed with this mode\n\n");
        exit(0);    
    }
    
    if ((params1.number == -2) && (params1.duration == -2)) {
        printf("\n Missing number of packets to send or time in seconds to transmit.\n Specify -n <number of packets> or -t <seconds to transmit>.\n");
        printf(" Set -n 0 to send infinite number of packets. \n\n");
        exit(0);
    }
    else if ((params1.number != -2) && (params1.duration != -2)) {
        printf("\n Only one option allowed at a time (-n or -t). \n Specify -n <number of packets> or -t <seconds to tramsmit>!\n\n");
        printf(" Set -n 0 to send infinite number of packets. \n\n");
        exit(0);
    } 
    
    if ((params1.number == -2) && (params1.duration > 0)) {
        params1.number = 0;
    }

    if (params1.packetsize != -2) {
        printf("\n Option -S not allowed in this mode\n\n");
        exit(0);    
    }
    if (params1.attack != -2) {
        printf("\n -a option not allowed in this mode!\n\n");
        exit(0);      
    }
    if ((strlen(params1.sizeramp) > 0 ) || (strlen(params1.rateramp) > 0 ) || (strlen(params1.rateRAMP) > 0 ) || (params1.period != -2)) {
        printf("\n Ramp options not allowed in this mode\n\n");
        exit(0);
    }

    if (strlen(params1.burstargs) ==0 ) {
        printf("\n Did you specify burst arguments with -L option? \n And don't forget the quotation marks! (for example: -L \"100 1000 200\")\n\n");
        exit(0);
    }

    //extract the number of packets in burst, delay between packets and delay between bursts
    //last 2 are multiplied by 1000 because we input the values in ms not ns
    for (count = 0; count <= strlen(params1.burstargs); count ++){
        ch = params1.burstargs[count];
        if((isblank(ch)) || (params1.burstargs[count] == '\0')){ 
            memcpy(tmp7, &params1.burstargs[flag],count-flag); 
            tmp7[count-flag]='\0';
            if (wordcount==0) 
                params1.burst_packets_in_burst = strtol(tmp7, &p, 10) ;
            else if (wordcount ==1)                     
                params1.burst_delay_between_packets = strtol(tmp7, &p, 10) * 1000;
            else if (wordcount ==2)                     
                params1.burst_delay_to_next_burst = strtol(tmp7, &p, 10) * 1000;

            wordcount += 1;
            flag = count;
        }
        
    }

    if (params1.burst_delay_between_packets > 999000000) {
            printf ("\n Warning! Rate is below 1pps, statistics will be displayed only when a packet will be sent.\n\n"); 
    }
    if (params1.burst_delay_to_next_burst > 999000000) {
            printf ("\n Warning! Rate is below 1pps, statistics will be displayed only when a packet will be sent.\n\n"); 
    }

    /*if (params1.startsize > params1.stopsize) {
        printf("\nstartsize is greater than stopzize (or did you forget the quotation marks?)\n\n");
        return 1;
    }
    if (params1.startsize < 60) {
        printf("\nstartsize must be >60\n\n");
        return 1;
    }
    if (params1.stopsize > MAX_MTU) {
        printf("\nstopsize must be <" MAX_MTU_STR "\n\n");
        return 1;
    }
    if (params1.ph.incl_len < params1.stopsize) {
        printf("\nPacket loaded from pcap file is shorter than stopsize!\n\n");
        return 1;   
    }*/

    if ((params1.my_pattern > 1) && (params1.my_pattern != 14)) {
        printf("\n Wrong pattern parameters. Choose one option:\n\n");
        printf("   Predifined pattern:  -x \n");
        printf("   Custom pattern:      -o <offset_counter> -q <offset_pattern> -w <pattern> \n\n");
        exit(0);
    }
    else if (strlen(params1.pattern) > 16) {
        printf("\n Pattern should not be longer than 16 chars!\n\n");
        exit(0);   
    }
    else if ((params1.offset_pattern < 0) || (params1.offset_pattern+strlen(params1.pattern) > params1.ph.incl_len)) {
        printf("\n Offset of the pattern is outside the packet size!\n\n");
        exit(0);   
    }
    else if ((params1.offset_counter < 0) || (params1.offset_counter > params1.ph.incl_len)) {
        printf("\n Offset of the counter is outside the packet size!\n\n");
        exit(0);   
    }
    else if ((params1.my_pattern > 1) && (params1.offset_counter >= params1.offset_pattern) && (params1.offset_counter <= params1.offset_pattern + strlen(params1.pattern))) {
        printf("\n Counter position and pattern position should not overlap!\n\n");
        exit(0);   
    }


    // if we insert my_pattern, this will be inserted from last 10 to last 2 bytes. Last 2 bytes themselves are reserved for counter 
    if (params1.my_pattern == 1) {
        memcpy(params1.ptr+params1.ph.incl_len-10, MY_PATTERN, 8);
        memset(params1.ptr+params1.ph.incl_len-2, 0, 1);
        memset(params1.ptr+params1.ph.incl_len-1, 1, 1);
    }

    // in case we use custom pattern and offset
    if(params1.my_pattern > 1) {
        memcpy(params1.ptr+params1.offset_pattern, params1.pattern, strlen(params1.pattern));
    }


    params1.size = params1.ph.incl_len;

    function_send_burst();

    return 1;
}
 
/*------------------------------------------------------------------------------*/
int function_send_burst() {

    int c;
    
    long  sentnumber = 0, lastnumber = 0;
    long long gap=0, gap2=0, gap2s=0, gap3s=0;
    struct timeval first;
    struct timespec first_ns, now_ns, last_ns, last2s_ns, last3s_ns;
    long burst_sent = 0;
   
    /* this is the time we started */
    gettimeofday(&first, NULL);

    clock_gettime(CLOCK_MONOTONIC, &first_ns);
    clock_gettime(CLOCK_MONOTONIC, &now_ns);
    clock_gettime(CLOCK_MONOTONIC, &last_ns);
    clock_gettime(CLOCK_MONOTONIC, &last2s_ns);
    clock_gettime(CLOCK_MONOTONIC, &last3s_ns);

    /* to send first packet immedialtelly */
    gap = 0;

    /*-----------------------------------------------------------------------------------------------*/
    for(; params1.number == 0 ? 1 : sentnumber < params1.number; ) {
    
            clock_gettime(CLOCK_MONOTONIC, &now_ns);
            gap = (now_ns.tv_sec*1000000000 + now_ns.tv_nsec) - (last_ns.tv_sec*1000000000 + last_ns.tv_nsec);
            gap2 = (now_ns.tv_sec*1000000000 + now_ns.tv_nsec) - (first_ns.tv_sec*1000000000 + first_ns.tv_nsec);
            gap2s = (now_ns.tv_sec*1000000000 + now_ns.tv_nsec) - (last2s_ns.tv_sec*1000000000 + last2s_ns.tv_nsec);
            gap3s = (now_ns.tv_sec*1000000000 + now_ns.tv_nsec) - (last3s_ns.tv_sec*1000000000 + last3s_ns.tv_nsec);
    
            if (burst_sent < params1.burst_packets_in_burst) {
                if (gap < params1.burst_delay_between_packets)
                    continue;
            }
            else {
                if (gap < params1.burst_delay_to_next_burst)
                    continue;
                else
                    burst_sent = 0;
                   
            }

            //send!
            c = sendto(params1.fd, params1.ptr, params1.size, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));

            last_ns.tv_sec = now_ns.tv_sec;
            last_ns.tv_nsec = now_ns.tv_nsec;
            gap = 0;

            if (c > 0) {
                sentnumber++;
                burst_sent++;
                if (params1.my_pattern == 1) 
                    (*(params1.ptr+params1.ph.incl_len-1))++;
                else if (params1.my_pattern > 1)
                    (*(params1.ptr+params1.offset_counter-1))++;
            }
            /* every display interval we print some output */
            if (gap2s > ((long long)params1.display_interval*1000000000)) {
                print_intermidiate(sentnumber, lastnumber, params1.size, params1.display_interval);
                lastnumber = sentnumber;
                last2s_ns.tv_sec = now_ns.tv_sec;
                last2s_ns.tv_nsec = now_ns.tv_nsec;
            }
                //exit if time has elapsed we exit
                if ((params1.duration > 0) && (gap2 >= (long long)(params1.duration*1000000000)))
                    break; 
            //}

            // every second we check if we need to adjust size, rate or both
            if (gap3s > 1000000000) {
                //reset timer
                last3s_ns.tv_sec = now_ns.tv_sec;
                last3s_ns.tv_nsec = now_ns.tv_nsec;

                //if we need do the rate (bandwidth) ramp mode
                /*if (params1.steprate != 0) { 
                    if ( (period2 > (params1.period-2)) && (params1.period>0) ) {
                        params1.rate = params1.rate + params1.steprate;
                        if ((params1.steprate > 0) && (params1.rate > params1.stoprate)) {
                            break;
                        }
                        else if ((params1.steprate < 0) && (params1.rate < params1.stoprate)) {
                            break;
                        }
                        params1.delay = (long long)(params1.rate*1000) / (params1.size*8);
                        params1.delay = 1000000000 / params1.delay;
                        period2 = 0;
                        
                    }
                    else
                    period2++;
                }*/
                
            }
    }
    print_final(first, sentnumber, params1.iftext);
    return 1;
    
}


/*------------------------------------------------------------------------------*/
int function_send() {

    int c;
    int period2 = 0;
    


    long  sentnumber = 0, lastnumber = 0;
    long long gap=0, gap2=0, gap2s=0, gap3s=0;
    struct timeval first;
    struct timespec first_ns, now_ns, last_ns, last2s_ns, last3s_ns;
   
    /* this is the time we started */
    gettimeofday(&first, NULL);

    clock_gettime(CLOCK_MONOTONIC, &first_ns);
    clock_gettime(CLOCK_MONOTONIC, &now_ns);
    clock_gettime(CLOCK_MONOTONIC, &last_ns);
    clock_gettime(CLOCK_MONOTONIC, &last2s_ns);
    clock_gettime(CLOCK_MONOTONIC, &last3s_ns);

    /* to send first packet immedialtelly */
    gap = 0;


    /*-----------------------------------------------------------------------------------------------*/
    //if the -1 for delay was choosed, just send as fast as possible, no output, no counters, no pattern, nothing
    if ((params1.delay==-1000) && (params1.number==0)) {
        for(;;)
            c = sendto(params1.fd, params1.ptr, params1.size, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));
    }
    /* with counters and delay between packets set */
    else {
        for(; params1.number == 0 ? 1 : sentnumber < params1.number; ) {
    
            clock_gettime(CLOCK_MONOTONIC, &now_ns);
            gap = (now_ns.tv_sec*1000000000 + now_ns.tv_nsec) - (last_ns.tv_sec*1000000000 + last_ns.tv_nsec);
            gap2 = (now_ns.tv_sec*1000000000 + now_ns.tv_nsec) - (first_ns.tv_sec*1000000000 + first_ns.tv_nsec);
            gap2s = (now_ns.tv_sec*1000000000 + now_ns.tv_nsec) - (last2s_ns.tv_sec*1000000000 + last2s_ns.tv_nsec);
            gap3s = (now_ns.tv_sec*1000000000 + now_ns.tv_nsec) - (last3s_ns.tv_sec*1000000000 + last3s_ns.tv_nsec);
    
            if (gap < params1.delay)
                continue;

            //send!
            c = sendto(params1.fd, params1.ptr, params1.size, 0, (struct sockaddr *)&params1.sa, sizeof (params1.sa));

            last_ns.tv_sec = now_ns.tv_sec;
            last_ns.tv_nsec = now_ns.tv_nsec;
            gap = 0;

            if (c > 0) {
                sentnumber++;
                if (params1.my_pattern == 1) 
                    (*(params1.ptr+params1.ph.incl_len-1))++;
                else if (params1.my_pattern > 1)
                    (*(params1.ptr+params1.offset_counter-1))++;
            }
            /* every display interval we print some output */
            if (gap2s > ((long long)params1.display_interval*1000000000)) {
                print_intermidiate(sentnumber, lastnumber, params1.size, params1.display_interval);
                lastnumber = sentnumber;
                last2s_ns.tv_sec = now_ns.tv_sec;
                last2s_ns.tv_nsec = now_ns.tv_nsec;
            }
                //exit if time has elapsed we exit
                if ((params1.duration > 0) && (gap2 >= (long long)(params1.duration*1000000000)))
                    break; 
            //}

            // every second we check if we need to adjust size, rate or both
            if (gap3s > 1000000000) {
                //reset timer
                last3s_ns.tv_sec = now_ns.tv_sec;
                last3s_ns.tv_nsec = now_ns.tv_nsec;

                //if we need do the rate (bandwidth) ramp mode
                if (params1.steprate != 0) { 
                    if ( (period2 > (params1.period-2)) && (params1.period>0) ) {
                        params1.rate = params1.rate + params1.steprate;
                        if ((params1.steprate > 0) && (params1.rate > params1.stoprate)) {
                            break;
                        }
                        else if ((params1.steprate < 0) && (params1.rate < params1.stoprate)) {
                            break;
                        }
                        params1.delay = (long long)(params1.rate*1000) / (params1.size*8);
                        params1.delay = 1000000000 / params1.delay;
                        period2 = 0;
                        
                    }
                    else
                    period2++;
                }
                //if we do the size ramp mode
                else if (params1.stepsize > 0) {
                    if ( (period2 > (params1.period-2)) && (params1.period>0) ) {
                        params1.size = params1.size + params1.stepsize;
                        if (params1.size > params1.stopsize) {
                            break;
                        }
                        period2 = 0;
                        if (params1.my_pattern == 1) {
                            memcpy(params1.ptr+params1.size-1, params1.ptr+params1.size-params1.stepsize-1, 1);
                            memcpy(params1.ptr+params1.size-10, MY_PATTERN, 8);
                        }
                    }
                    else
                        period2++;
                }
                //if we want to keep the rate the same, we need to change the delay
                if (params1.ConstantRate == 1) {
                    params1.delay = (long long)(1000 * params1.rate) / (params1.size*8);
                    params1.delay = 1000000000  / params1.delay;    
                }
            }
        }
        print_final(first, sentnumber, params1.iftext);
        return 1;
    }
    return 1;
}

/*------------------------------------------------------------------------------*/
int interface_setup()
{    
    int i=0;

    if (strlen(params1.iftext) == 0 ) {
        printf("\n You need to specify output interface (-i interface_name)\n\n");
        exit(1);
    }

    /* do we have the rights to do that? */
    if (getuid() && geteuid()) {
        //printf("Sorry but need the su rights!\n");
        printf("\nSorry but need the su rights!\n\n");
        exit(1);
    }

    /* open socket in raw mode */
    params1.fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (params1.fd == -1) {
        //printf("Error: Could not open socket!\n");
        printf("\nError: Could not open socket!\n\n");
        exit(1);
    }

    // form mode 9 (receiver) - put the socket in non-blocking mode:
    if (params1.mode == 9) {
        if(fcntl(params1.fd, F_SETFL, fcntl(params1.fd, F_GETFL) | O_NONBLOCK) < 0) {
            printf("socket non-blocking failed\n");
            exit(1);
        }
    }

    /* which interface would you like to use? */
    memset(&params1.ifr, 0, sizeof(params1.ifr));
    memcpy (params1.ifr.ifr_name, params1.iftext, sizeof(params1.ifr.ifr_name) - 1);
    params1.ifr.ifr_name[sizeof(params1.ifr.ifr_name)-1] = '\0';

    /* does the interface exists? */
    if (ioctl(params1.fd, SIOCGIFINDEX, &params1.ifr) == -1) {
        printf("\nNo such interface: %s\n\n", params1.iftext);
        close(params1.fd);
        exit(1);
    }

    /* is the interface up? */
    ioctl(params1.fd, SIOCGIFFLAGS, &params1.ifr);
    if ( (params1.ifr.ifr_flags & IFF_UP) == 0) {
        printf("\nInterface %s is down\n\n", params1.iftext);
        close(params1.fd);
        exit(1);
    }

    if (params1.mode == 9) {
        /* Set interface to promiscuous mode - do we need to do this every time? */
        memcpy(params1.ifopts.ifr_name, params1.iftext, sizeof(params1.ifopts.ifr_name)-1);
        ioctl(params1.fd, SIOCGIFFLAGS, &params1.ifopts);
        params1.ifopts.ifr_flags |= IFF_PROMISC;
        ioctl(params1.fd, SIOCSIFFLAGS, &params1.ifopts);
    }

    /* just write in the structure again */
    ioctl(params1.fd, SIOCGIFINDEX, &params1.ifr);

    /* well we need this to work, don't ask me what is it about */
    memset(&params1.sa, 0, sizeof (params1.sa));
    params1.sa.sll_family    = AF_PACKET;
    params1.sa.sll_ifindex   = params1.ifr.ifr_ifindex;
    params1.sa.sll_protocol  = htons(ETH_P_ALL);

    /* for mode 9 (receiver) - you need this to receive from the right interface */
    if (params1.mode == 9) {
        i = bind(params1.fd, (struct sockaddr*)&params1.sa, sizeof(params1.sa));
        if (i == -1)
        {
            perror("Interface bind error");
            exit(1);
        }
    }    

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
        exit(1);
    }

    /* first we read the pcap file header */
    freads = fread(params1.pkt_temp, sizeof(params1.fh), 1, file_p);
    /* if EOF, exit */
    if (freads == 0) {
        printf("\nPcap file not correct?\n\n");
        exit(1);
    }

    memcpy(&params1.fh, params1.pkt_temp, 24);

    /* if magic number in NOK, exit */
    if (params1.fh.magic != PCAP_MAGIC) {
        printf("\nWrong pcap file format?\n\n");
        exit(1);
    }

    // we can select which packet we want to send
    if (params1.seqnum == -2)
        params1.seqnum = 1;
    for (i=0; i < params1.seqnum; i++) {
        /* next the  pcap packet header */
        freads = fread(params1.pkt_temp, sizeof(params1.ph), 1, file_p);
    
            /* if EOF, exit */
            if (freads == 0) {
                printf("\nWrong sequence number? Or wrong pcap file format?\n\n");
                exit(1);
            }
    
            /* copy the 16 bytes into ph structure */
            memcpy(&params1.ph, params1.pkt_temp, 16);    
            params1.ptr = params1.pkt_temp + sizeof(params1.ph);
    
            /* and the packet itself, but only up to the capture length */
            freads = fread(params1.ptr, params1.ph.incl_len, 1, file_p);
    
            /* if EOF, exit */
            if (freads == 0) {
                printf("\nWrong sequence number? Or wrong pcap file format?\n\n");
                exit(1);
        }
    }
    fclose(file_p);

    return 1;
}

/*------------------------------------------------------------------------------*/
void print_intermidiate(long packets_sent, long packets_last_sent, int packet_size, int print_interval) {
    
    long  mbps, packets_pps, link;
    float Mbps, Link;

    packets_pps = (packets_sent - packets_last_sent) / print_interval;
    mbps = packets_pps * packet_size / 125; // 8 bits per byte / 1024 for kbit
    Mbps = (float)mbps/1000;
    link = packets_pps * (packet_size + 24) / 125; /* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
    Link = (float)link/1000;
    
    printf("  Sent %ld packets on %s; %d bytes packet length; %ld packets/s; %.3f Mbit/s data rate; %.3f Mbit/s link utilization\n", packets_sent, params1.iftext, packet_size, packets_pps, Mbps, Link);
    fflush(stdout);
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
    close(params1.fd);
    if (params1.mode == 5)
        cleanupRules(params1.num_rules);  
    exit(0);  
}

/*------------------------------------------------------------------------------*/
void onexit(int signum)
{
    (void)signum;
    //printf(" ... Exiting\n");
    STOP = 1;
    close(params1.fd);

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
    int count, flag=0;
    
    int wordcount = 0;
    char *p;
    char tmp7[10];
    char ch;
    
    if (params1.paramnum == 1) {  
        usage_5();
        exit(0);
    }

    //check if the options are ok
    if ((params1.attack < 1) || (params1.attack > 4)) {
        printf("\n Missing amount of attack traffic. Select: -a <1-4>");
        printf("\n 0 for innocent traffic, 1 for 25%% attack, 2 for 50%% attack, 3 for 75%% attack, 4 for 100%% attack\n\n");
        exit(0);
    }

    //check if the options are ok
    if ((params1.delay_mode != 1) && (params1.delay_mode != 2) && (params1.delay_mode != 4) && (params1.delay_mode != 8)) {
        printf("\n Wrong or missing delay between packets or bandwidth parameter.\n\n Specify one of the following options:\n");
        printf("   -D <nanoseconds>    - delay between packets in nanoseconds\n");
        printf("   -d <microseconds>   - delay between packets in microseconds\n");
        printf("   -d 0                - maximum speed with counters\n");
        printf("   -b <bandwidth>      - desired bandwidth in kbit/s\n");
        printf("   -B <bandwidth>      - desired bandwidth in Mbit/s\n\n");
        exit(0);    
    }
    else if ((params1.delay_mode == 1) && (params1.delay == -1)) {
        printf("\n Option -d -1 not allowed with this mode\n\n");
        exit(0);
    }
    
    if (params1.delay_mode == 1)
        params1.delay = params1.delay * 1000;
    else if (params1.delay_mode == 2) 
        params1.delay = params1.delay;
    else if (params1.delay_mode == 4)
        params1.delay = (long long)(1000000 * (long long)params1.ph.incl_len * 8 / params1.bw);
    else if (params1.delay_mode == 8) 
        params1.delay = (long long)(1000 * (long long)params1.ph.incl_len * 8 / params1.BW);

    if (params1.delay > 999000000) {
            printf ("\n Warning! Rate is below 1pps, statistics will be displayed only when a packet will be sent.\n\n"); 
    }
    
    if ((params1.number == -2) && (params1.duration == -2)) {
        printf("\n Missing number of packets to send or time in seconds to transmit.\n Specify -n <number of packets> or -t <seconds to transmit>.\n");
        printf(" Set -n 0 to send infinite number of packets. \n\n");
        exit(0);
    }
    else if ((params1.number != -2) && (params1.duration != -2)) {
        printf("\n Only one option allowed at a time (-n or -t). \n Specify -n <number of packets> or -t <seconds to tramsmit>!\n\n");
        printf(" Set -n 0 to send until the ramp finishes. \n\n");
        exit(0);
    }
    
    if ((params1.number == -2) && (params1.duration > 0)) {
        params1.number = 0;
    }

    if (strlen(params1.rateramp) > 0 ) {
        printf("\n Options -z and -Z are not allowed in this mode.\n\n");
        exit(0);
    }

    if (params1.seqnum != -2 ) {
        printf("\n Option -c not allowed in this mode.\n\n");
        exit(0);
    }

    if ((strlen(params1.sizeramp) ==0 ) && (params1.packetsize == -2)) {
        printf("\n Did you specify packet size with -S or size ramp values with -s option (in bytes)? \n And don't forget the quotation marks! (for example: -s \"100 1000 200\")\n\n");
        exit(0);
    }

    if ((strlen(params1.sizeramp) > 0) && (params1.period == -2)) {
        printf("\n Did you specify duration of one step (in seconds) with -p option?\n\n");
        exit(0);
    }

    if (params1.my_pattern > 0) {
        printf("\n Pattern options not allowed in this mode!\n\n");
        exit(0);
    }

    /* read snort rule file */
    params1.num_rules = readSnortRules(params1.filename);
    if (params1.num_rules == 0) {
        /* if there are no rules, then die! */
        fprintf(stderr, "Rules file is empty!\n");
        exit(EXIT_FAILURE);
    }
    
    if (strlen(params1.sizeramp) > 0 ) {
        for (count = 0; count <= strlen(params1.sizeramp); count ++){
            ch = params1.sizeramp[count];
            if((isblank(ch)) || (params1.sizeramp[count] == '\0')){ 
                memcpy(tmp7, &params1.sizeramp[flag],count-flag); 
                tmp7[count-flag]='\0';
                if (wordcount==0) 
                    params1.startsize = strtol(tmp7, &p, 10);
                else if (wordcount == 1)
                    params1.stopsize = strtol(tmp7, &p, 10);
                else if (wordcount == 2)
                    params1.stepsize = strtol(tmp7, &p, 10);
                
                wordcount += 1;
                flag = count;
            }
            
        }
        if (params1.startsize > params1.stopsize) {
            printf("\nstartsize is greater than stopzize\n\n");
            close(params1.fd);
            cleanupRules(params1.num_rules);
            return 1;
        }
        if (params1.startsize < 60) {
            printf("\nstartsize must be >60\n\n");
            close(params1.fd);
            cleanupRules(params1.num_rules);            
            return 1;
        }
        if (params1.stopsize > MAX_MTU) {
            printf("\nstopsize must be <%d\n\n", MAX_MTU);
            close(params1.fd);
            cleanupRules(params1.num_rules);            
            return 1;
        }
        params1.size = params1.startsize;
    }
    else
        params1.size = params1.packetsize;

    function_send();
              
    return 1;
}

void usage(void) {
    printf("\nUsage: ./packETHcli -m <mode > -i <interface> -f <file> [options]\n");
    printf(" \n");
    printf(" There are diffent modes, use ./packETHcli -m <mode> to get detailed help for particular mode\n");
    printf(" \n");
    printf("   -m 1   - SEND PACKET ONCE (default mode)\n");
    printf("   -m 2   - SEND PACKETS CONTINUOUSLY WITH CONSTANT RATE:\n");
    printf("   -m 3   - SEND PACKETS CONTINUOUSLY WITH VARIABLE RATE (SPEED RAMP)\n");
    printf("   -m 4   - SEND PACKETS CONTINUOUSLY WITH VARIABLE SIZE (SIZE RAMP)\n");
    printf("   -m 5   - SEND SEQUENCE OF PACKETS (IDS TEST MODE)\n");
    printf("   -m 6   - SEND PACKETS IN BURST MODE (CONSTANT BURST)\n");
    printf("   -m 9   - RECEIVER MODE (count packets sent by packETHcli or packETH\n");
    printf("\n");
    //printf(" -f <file> - file name where packet is stored in pcap format (or attack definitions file in Snort rule format in mode 5) \n");
    //printf(" -I <seconds> - time interval to display results (default 1s) \n");
    printf("\n");
    printf("FOR EXAMPLES SEE: ./packETHcli -e \n\n");
}

void usage_1(void) {
    printf(" -m 1   - SEND PACKET ONCE (default mode): send packet from the pcap file once \n");
    printf("          Usage: ./packETHcli -m 1 -i <interface> -f <pacp file> [-c]\n");  
    printf("          Optional parameter:\n");
    printf("               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)\n");
    printf("                              to see sequence numbers of packets inside pcap file: tcpdump -# -r filename\n");
    printf("          Example: ./packETHcli -i eth0 -f packet.pcap\n\n");
}

void usage_2(void) {
    printf(" -m 2   - SEND PACKETS CONTINUOUSLY WITH CONSTANT RATE: send (first) packet from pcap file at constant rate\n");
    printf("          Usage: ./packETHcli -m 2 -i <interface> -f <pcap file> [options]\n");  
    printf("          Required parameters:\n");
    printf("              Number of packets to send or duration in seconds (only one option possible)\n");
    printf("               -n <number, 0> - number of packets to send or 0 for infinite\n");
    printf("               -t <seconds> - seconds to transmit\n");
    printf("              Delay between packets or sendrate (only one option possible)\n");
    printf("               -D <ns>        - delay between packets in nano seconds;\n");
    printf("               -d <us>        - delay between packets in micro seconds;\n");
    printf("               -d 0           - maximum speed with counters\n");
    printf("               -d -1          - maximum speed without counters\n");
    printf("               -b <bandwidth> - desired sending rate in kbit/s\n");
    printf("               -B <bandwidth> - desired sending rate in Mbit/s\n");
    printf("          Optional parameters:\n");
    printf("               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)\n");
    printf("               -I <seconds> - time interval to display results (default 1s) \n");
    printf("              Insert predifined pattern into packet: \n");
    printf("               -x             - insert pattern \"a9b8c7d6\" and counter inside last 10 bytes of packet\n");
    printf("              Insert custom pattern at custom positon and counter at custom position\n");
    printf("               -q <offset>    - where should the pattern be (bytes offset)\n");
    printf("               -w <pattern>   - what should be the pattern to match\n");
    printf("               -o <offset>    - where should the inceremented counter be (bytes offset)\n");
    printf("               \n");
    printf("          Example: ./packETHcli -i eth0 -m 2 -B 100 -n 10000 -f p1.pcap \n\n");
 }

 void usage_3(void) {
    printf(" -m 3   - SEND PACKETS CONTINUOUSLY WITH VARIABLE RATE (SPEED RAMP)\n");
    printf("          Usage: ./packETHcli -m 3 -i <interface> -f <pcap file> [options]\n");  
    printf("          Required parameters:\n");
    printf("              Number of packets to send or duration in seconds (only one option possible)\n");
    printf("               -n <number, 0> - number of packets to send or 0 for infinite\n");
    printf("               -t <seconds> - seconds to transmit\n");
    printf("              Startrate, Stoprate, Steprate and Step duration (only one option possible):\n");
    printf("               -z \"<startrate stoprate steprate)\" in kbit/s \n");
    printf("               -Z \"<startrate stoprate steprate)\" in Mbit/s \n");
    printf("              Step duration:\n" );
    printf("               -p <seconds> - period between steps in seconds \n");
    printf("          Optional parameters:\n");
    printf("               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)\n");
    printf("               -I <seconds> - time interval to display results (default 1s) \n");
    printf("              Insert predifined pattern into packet: \n");
    printf("               -x             - insert pattern \"a9b8c7d6\" and counter inside last 10 bytes of packet\n");
    printf("              Insert custom pattern at custom positon and counter at custom position\n");
    printf("               -q <offset>    - where should the pattern be (bytes offset)\n");
    printf("               -w <pattern>   - what should be the pattern to match\n");
    printf("               -o <offset>    - where should the inceremented counter be (bytes offset)\n");
    printf("               \n");
    printf("          Example: ./packETHcli -i eth1 -m 3 -t 3600 -Z \"500 100 1\" -p 5 -f p1.pcap \n\n");
}

void usage_4(void) {
    printf(" -m 4   - SEND PACKETS CONTINUOUSLY WITH VARIABLE SIZE (SIZE RAMP)\n");
    printf("          Usage: ./packETHcli -m 4 -i <interface> -f <pcap file> [options]\n");  
    printf("          Required parameters:\n");
    printf("              Number of packets to send or duration in seconds (only one option possible)\n");
    printf("               -n <number, 0> - number of packets to send or 0 for infinite\n");
    printf("               -t <seconds> - seconds to transmit\n");
    printf("              Delay between packets or sendrate (only one option possible). Choose first option for constant pps and second one for constant bandwidth\n");
    printf("               -d <us, 0> - delay between packets in micro seconds; select 0 for maximum speed\n");
    printf("               -D <ns, 0, -1> - delay between packets in nano seconds; select 0 for maximum speed with counters; select -1 for max speed without counters)\n");
    printf("               -b <bandwidth> - desired sending rate in kbit/s\n");
    printf("               -B <bandwidth> - desired sending rate in Mbit/s\n");
    printf("              Startsize, Stopsize, Stepsize and Step duration number\n");
    printf("               -s \"<startsize stopsize stepsize>\" in bytes (please note that TCP&UDP checksums are not (yet :) ) recalculated!!!) \n");
    printf("               -p <seconds> - period between steps in seconds\n");
    printf("          Optional parameters:\n");
    printf("               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)\n");
    printf("               -I <seconds> - time interval to display results (default 1s) \n");
    printf("              Insert predifined pattern into packet: \n");
    printf("               -x             - insert pattern \"a9b8c7d6\" and counter inside last 10 bytes of packet\n");
    printf("          Example: ./packETHcli -i eth1 -m 4 -d 2000 -n 0 -s \"100 1500 100\" -p 5 -f p1.pcap\n\n");
}

void usage_5(void) {
    printf(" -m 5   - SEND SEQUENCE OF PACKETS (IDS TEST MODE)\n");
    printf("          Usage: ./packETHcli -m 5 -i <interface> -f <attack definitions file> [options]\n");
    printf("          Required parameters\n");
    printf("            -f <attack definitions file in Snort rule format> \n"); 
    printf("            -a <numbers from 0 to 4> - innocent traffic for 0, 25%% attack for 1, 50%% attack for 2, 75%% attack for 3, 100%% attack for 4> \n");
    printf("            -S <packet size in bytes OR -s \"<startsize stopsize stepsize>\" -p <step period>\n");
    printf("            -d <us, 0, -1> - delay between packets OR -b <bandwidth in kbit/s>  OR -B <bandwidth in Mbit/s\n");
    printf("            -n <number, 0> - number of packets to send (0 for infinite) OR -t <duration in seconds>\n");
    printf("           Example: ./packETHcli -i lo -f sample_snort_rules.txt -B 10 -m 5 -t 60 -S 1000 -a 2\n\n");
    printf("\n");
}

void usage_6(void) {
    printf(" -m 6   - SEND PACKETS IN BURST MODE (CONSTANT BURST)\n");
    printf("          Usage: ./packETHcli -m 4 -i <interface> -f <pcap file> [options]\n");  
    printf("          Required parameters:\n");
    printf("              Number of packets to send or duration in seconds (only one option possible)\n");
    printf("               -n <number, 0> - number of packets to send or 0 for infinite\n");
    printf("               -t <seconds> - seconds to transmit\n");
    printf("              Number of packets in burst, delay between packets in burst (us), delay till next burst (us)\n");
    printf("               -L \"<packets_in_burst  delay_between_packets_in_burst_us  delay_between_bursts_us>\" \n");
    printf("          Optional parameters:\n");
    printf("               -c <number>  - sequence number of packet stored in pcap file (by default first packet will be sent)\n");
    printf("               -I <seconds> - time interval to display results (default 1s) \n");
    printf("              Insert predifined pattern into packet: \n");
    printf("               -x             - insert pattern \"a9b8c7d6\" and counter inside last 10 bytes of packet\n");
    printf("          Example: ./packETHcli -i eth1 -m 6 -n 0 -L \"100 1 100\" -f p1.pcap\n\n");
}

void usage_9(void)
{
    printf(" -m 9   - RECEIVER MODE: COUNT PACKETS (FROM packETHcli)\n");
    printf("          Usage: ./packETHcli -m 9 -i <interface> [-x OR -o <offset counter> -q <offset pattern> -w <pattern>]\n");
    printf("          Optional parameter:\n");
    printf("          To count packets with predifined pattern sent by packETHcli use -x option on both sides (sender and receiver)  :\n");
    printf("            -x   - Last 10 bytes in received packets will be checked for pattern \"a8b7c7d6\" and counter\n");
    printf("          To count packets with custom pattern at custom positon and counter at custom position:\n");
    printf("            -q <offset>   - where should the pattern be (bytes offset)\n");
    printf("            -w <pattern>  - what should be the pattern to match\n");
    printf("            -o <offset>   - where should the inceremented counter be (bytes offset)\n");
    printf("          Examples:\n");
    printf("          ./packETHcli -m 9 -i eth0\n");
    printf("          ./packETHcli -m 9 -i eth0 -x\n");
    printf("          ./packETHcli -m 9 -i eth0 -o 60 -q 70 -w 12345678\n");
    printf("\n");
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
    printf("   ./packETHcli -i eth0 -m 2 -b 1500 -t 30 -f p1.pcap -I 5                       - send packets with rate 1500 kbit/s for 30s, display results every 5s\n");        
    printf("   ./packETHcli -i eth0 -m 2 -B 100 -n 10000 -f p1.pcap -c 7                     - send 7th packet 10000 times, with rate 100 Mbit/s\n");        
    printf("   ./packETHcli -i eth0 -m 2 -B 100 -n 0 -f p1.pcap -x                           - send infinite times with rate 100 Mbit/s, add predifined pattern and counter\n");        
    printf("   ./packETHcli -i eth0 -m 2 -B 100 -n 0 -f p1.pcap -o 60 -q 70 -w 12345         - send infinite times with rate 100 Mbit/s, add counter at byte 60 and pattern 12345 at byte 70\n");        
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
    printf("   ./packETHcli -i eth1 -m 5 -f sample_snort_rules.txt -d 1000 -t 60 -s \"100 1000 100\" -a 4 -p 10\n");
    printf("                                                                                  - send 100%% IDS traffic, 1000pps for 60 seconds, increase packet size from 100 to 1000 bytes\n");
    printf("\n");
    printf("  mode 6 - send packets in burst mode:\n");
    printf("   ./packETHcli -i eth1 -m 6 -n 0 -L \"100 1000 200000\"  -f p1.pcap              - send a burst of 100 packets with 1ms between them then wait for 200ms and send next burst again\n");
    printf("   ./packETHcli -i eth1 -m 6 -n 0 -L \"100 0 100000\"  -f p1.pcap                 - send a burst of 100 packets as fast as possible then then wait for 100ms and send next burst again\n");
    printf("\n");
    printf("  mode 9 - receive and count packets sent by packETHcli:\n");
    printf("   ./packETHcli -i eth1 -m 9 -x                                                  - receive and count packets sent by packETHcli with -x option\n");
    printf("   ./packETHcli -i eth1 -m 9 -o 60 -q 70 -w 12345                                - receive and count packets that have counter at byte 60 and the pattern is 12345 at byte 70\n");
    printf("\n");
    printf("\n\n");
    exit(0);    
}

