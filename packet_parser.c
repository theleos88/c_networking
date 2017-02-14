/* Demonstration program of reading packet trace files recorded by pcap
 * (used by tshark and tcpdump) and dumping out some corresponding information
 * in a human-readable form.
 *
 * Note, this program is (NOT) limited to processing trace files that contains
 * only UDP packets.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <pcap.h>
typedef u_int tcp_seq;


/* We've included the UDP header struct for your ease of customization.
 * For your protocol, you might want to look at netinet/tcp.h for hints
 * on how to deal with single bits or fields that are smaller than a byte
 * in length.
 *
 * Per RFC 768, September, 1981.
 */
struct udp_hdr {
    u_short uh_sport;       /* source port */
    u_short uh_dport;       /* destination port */
    u_short uh_ulen;        /* datagram length */
    u_short uh_sum;         /* datagram checksum */
};

struct tcp_hdr {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};



uint64_t print_value( void* packet, int size ){
    uint8_t* pointer = (uint8_t*) packet;
    uint64_t data=0;

    int i=0;
    for (i=0;i<size;i++){
        printf("%02x", *pointer);
        data+=(*pointer);
        pointer++;
    }
    printf(" ");
    return data;
}

void print_tcp(struct ip *ip, struct tcp_hdr *tcp){
    printf("%08x %08x %04x %04x %04x ", (uint32_t) ip->ip_src.s_addr, (uint32_t) ip->ip_dst.s_addr, ip->ip_p, tcp->th_sport, tcp->th_dport );
}

void print_udp(struct ip *ip, struct udp_hdr *udp){
    printf("%08x %08x %04x %04x %04x ", (uint32_t) ip->ip_src.s_addr, (uint32_t) ip->ip_dst.s_addr, ip->ip_p, udp->uh_sport, udp->uh_dport );
}

/* Some helper functions, which we define at the end of this file. */

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);

/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(struct timeval ts, const char *reason);

/* Report the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);

/* dump_UDP_packet()
 *
 * This routine parses a packet, expecting Ethernet, IP, and UDP headers.
 * It extracts the UDP source and destination port numbers along with the UDP
 * packet length by casting structs over a pointer that we move through
 * the packet.  We can do this sort of casting safely because libpcap
 * guarantees that the pointer will be aligned.
 *
 * The "ts" argument is the timestamp associated with the packet.
 *
 * Note that "capture_len" is the length of the packet *as captured by the
 * tracing program*, and thus might be less than the full length of the
 * packet.  However, the packet pointer only holds that much data, so
 * we have to be careful not to read beyond it.
 */
void dump_packet(const unsigned char *packet, struct timeval ts,
            unsigned int capture_len)
{
    struct ip *ip;
    struct udp_hdr *udp;
    struct tcp_hdr *tcp;
    
    int size = capture_len;
    
    struct ether_header *eth_p;

    unsigned int IP_header_length;

    if (capture_len < sizeof(struct ether_header))
        {
        /* We didn't even capture a full Ethernet header, so we
         * can't analyze this any further.
         */
        too_short(ts, "Ethernet header");
        return;
        }

    /* Check MAC address and IP src and dest */
    eth_p = (struct ether_header*)packet;

    /* Skip over the Ethernet header. */
    packet += sizeof(struct ether_header);
    capture_len -= sizeof(struct ether_header);

    if (capture_len < sizeof(struct ip))
        { /* Didn't capture a full IP header */
        too_short(ts, "IP header");
        return;
        }

    ip = (struct ip*) packet;
    IP_header_length = ip->ip_hl * 4;   /* ip_hl is in 4-byte words */

    if (capture_len < IP_header_length)
        { /* didn't capture the full IP header including options */
        too_short(ts, "IP header with options");
        return;
        }
    
    packet += IP_header_length;

    switch (ip->ip_p){
        case IPPROTO_TCP:
            tcp = (struct tcp_hdr*)packet;
            print_tcp(ip, tcp);
            printf("%d\n", size);
            break;
        case IPPROTO_UDP:
            udp = (struct udp_hdr*) packet;
            print_udp(ip, udp);
            printf("%d\n", size);
            break;
        default:
            print_value(eth_p->ether_dhost, ETH_ALEN);
            print_value(eth_p->ether_shost, ETH_ALEN);
            printf("%d %d\n", ip->ip_p, size);
            break;
    }


    /* Skip over the IP header to get to the UDP header. */
    capture_len -= IP_header_length;

    if (capture_len < sizeof(struct udp_hdr))
    {
        too_short(ts, "UDP header");
        return;
    }
}


int main(int argc, char *argv[])
    {
    pcap_t *pcap;
    const unsigned char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;

    /* Skip over the program name. */
    ++argv; --argc;

    /* We expect exactly one argument, the name of the file to dump. */
    if ( argc != 1 )
        {
        fprintf(stderr, "program requires one argument, the trace file to dump\n");
        exit(1);
        }

    pcap = pcap_open_offline(argv[0], errbuf);
    if (pcap == NULL)
        {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        exit(1);
        }

    /* Now just loop through extracting packets as long as we have
     * some to read.
     */
    int i=0;
    printf("# Pktsrc, Pktdst, Protocol, [Portsrc, portdst], Size\n");
    while ((packet = pcap_next(pcap, &header)) != NULL){
        i++;
        dump_packet(packet, header.ts, header.caplen);
    }
    printf("Read %d packets\n", i);

    // terminate
    return 0;
    }


/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts)
    {
    static char timestamp_string_buf[256];

    sprintf(timestamp_string_buf, "%d.%06d",
        (int) ts.tv_sec, (int) ts.tv_usec);

    return timestamp_string_buf;
    }

void problem_pkt(struct timeval ts, const char *reason)
    {
//    fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
    }

void too_short(struct timeval ts, const char *truncated_hdr)
    {
    fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
        timestamp_string(ts), truncated_hdr);
    }
