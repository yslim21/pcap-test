#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <libnet.h>
//#include "myheader.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

//print mac
void print_mac_addr(const u_char* addr) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", addr[i]);
        if (i < 5)
            printf(":");
    }
    printf("\n");
}

//print data
void print_payload(const u_char* payload, int len) {
    int max_len = len > 20 ? 20 : len;
    for (int i = 0; i < max_len; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr *)packet;
        if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
            struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
            if (ip_hdr->ip_p == IPPROTO_TCP) { // TCP 프로토콜인 경우
                struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl * 4));

                printf("------------Ethernet Header------------\n");
                printf("Src MAC: "); print_mac_addr(eth->ether_shost);
                printf("Dst MAC: "); print_mac_addr(eth->ether_dhost);

                printf("------------IP Header------------\n");
                printf("Src IP: %s\n", inet_ntoa(ip_hdr->ip_src));
                printf("Dst IP: %s\n", inet_ntoa(ip_hdr->ip_dst));
                
                //print TCP Header
                printf("------------TCP Header------------\n");
                printf("Src Port: %d\n", ntohs(tcp_hdr->th_sport));
                printf("Dst Port: %d\n", ntohs(tcp_hdr->th_dport));
                
                // ip header, tcp header length inforamtion
                int ip_header_len = ip_hdr->ip_hl * 4;
                int tcp_header_len = tcp_hdr->th_off * 4;
                int payload_offset = sizeof(struct libnet_ethernet_hdr) + ip_header_len + tcp_header_len;
                int payload_len = ntohs(ip_hdr->ip_len) - ip_header_len - tcp_header_len;
                
                // print data
                printf("------------Payload (max 20 bytes)------------\n");
                if (payload_len > 0) {
                    print_payload(packet + payload_offset, payload_len);
                } else {
                    printf("(No Data)\n");
                }

                printf("\n");
            }
        }
    }

    pcap_close(pcap);
    return 0;
}

