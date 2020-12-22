#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <pcap.h>

#define MAC_ADDLEN 18

char *mac_ntoa(u_char *d) {
    static char str[MAC_ADDLEN];
    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
    return str;
}

int main(int argc, char **argv)
{
	char *file_name;
	if(argc < 3){
		 printf("Error...\n");
		 return 0;
	}
	else{
		file_name = strdup(argv[2]);
	}
	// open file
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *handler = pcap_open_offline(file_name, errbuff);
	
	// header
    struct pcap_pkthdr *header;
    struct ether_header *eth_header;
    
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
	
	u_char *packet;
    u_int size_ip;
    u_int size_tcp;
    time_t tmp;
    struct tm ts;
	char dateBuf[100];
	int res;
	
	int packet_cnt = 0;
	while((res = pcap_next_ex(handler, &header, (const u_char **)&packet)) >= 0){
        if(res == 0) continue;
        char dst_mac_addr[MAC_ADDLEN] = {};
    	char src_mac_addr[MAC_ADDLEN] = {};
		u_int16_t type;
	
		// formate time
		tmp = header->ts.tv_sec;
		ts = *localtime(&tmp);
		strftime(dateBuf, sizeof(dateBuf), "%a %Y-%m-%d %H:%M:%S", &ts);
		
		eth_header = (struct ether_header *) packet;
		strncpy(src_mac_addr, mac_ntoa(eth_header->ether_shost), sizeof(src_mac_addr)); // src MAC
		strncpy(dst_mac_addr, mac_ntoa(eth_header->ether_dhost), sizeof(dst_mac_addr)); // dst MAC
		type = ntohs(eth_header->ether_type); // Ethernet type
		// print info	
		printf("Packet #%d:\n",++packet_cnt);
		printf("Time: %s\n", dateBuf);
		printf("Length: %d bytes\n", header->len);
    	printf("Capture length: %d bytes\n", header->caplen);
		printf("┌─────────────────────────────────────────────────────────────────────────────┐\n");
		printf("│ Source MAC Address:                                        %17s│\n", src_mac_addr);
		printf("├─────────────────────────────────────────────────────────────────────────────┤\n");
		printf("│ Destination MAC Address:                                   %17s│\n", dst_mac_addr);
		printf("└─────────────────────────────────────────────────────────────────────────────┘\n");
		
		if(type  == ETHERTYPE_IP)
		{
			// IP
			struct ip *ip_header;
			u_int version, header_len;
			u_char tos, ttl;
			u_int16_t total_len, id, offset, checksum;
			char src_ip[INET_ADDRSTRLEN];   // source IP
			char dst_ip[INET_ADDRSTRLEN];   // destination IP
			char Protocol[5];
			ip_header = (struct ip*)(packet + sizeof(struct ether_header));
			version = ip_header->ip_v;
			// Protocol
			if(ip_header->ip_p == IPPROTO_UDP){
				strncpy(Protocol,"UDP",3);
			}
			else if(ip_header->ip_p == IPPROTO_TCP){
				strncpy(Protocol,"TCP",3);
			}
			else{
				strncpy(Protocol,"   ",3);
			}
			inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
			printf("┌───────────────────┬─────────────────┬─────────────┐\n");
			printf("│ Ethernet type: IP │IV: %u            │Protocol: %s│\n",version,Protocol);
			printf("├───────────────────┴─────────────────┴─────────────┤\n");
			printf("│ Source IP Address:                 %15s│\n",src_ip);
			printf("├───────────────────────────────────────────────────┤\n");
			printf("│ Destination IP Address:            %15s│\n",dst_ip);
			printf("├─────────────────────────┬─────────────────────────┤\n");
			
			if(ip_header->ip_p == IPPROTO_UDP || ip_header->ip_p == IPPROTO_TCP)
			{
				struct ip *ip = (struct ip *)(packet + ETHER_HDR_LEN);
				struct udphdr *udp = (struct udphdr *)(packet + ETHER_HDR_LEN + (ip->ip_hl << 2));
				u_int16_t source_port = ntohs(udp->uh_sport);
				u_int16_t destination_port = ntohs(udp->uh_dport);
				printf("│ Source Port:       %5u│ Destination Port:  %5u│\n", source_port, destination_port);
			}
			
			printf("└─────────────────────────┴─────────────────────────┘\n");
		}
		else if(ntohs(eth_header->ether_type) == ETHERTYPE_PUP){
			printf("┌───────────────────────────────────────────────────┐\n");
			printf("│ Ethernet type: PUP                                │\n");
			printf("└───────────────────────────────────────────────────┘\n");
		}
		else if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
			printf("┌───────────────────────────────────────────────────┐\n");
			printf("│ Ethernet type: ARP                                │\n");
			printf("└───────────────────────────────────────────────────┘\n");
		}
		else if(ntohs(eth_header->ether_type) == ETHERTYPE_REVARP){
			printf("┌───────────────────────────────────────────────────┐\n");
			printf("│ Ethernet type: Reverse ARP                        │\n");
			printf("└───────────────────────────────────────────────────┘\n");
		}
		else{
			printf("┌───────────────────────────────────────────────────┐\n");
			printf("│ Ethernet type: No Support!!!                      │\n");
			printf("└───────────────────────────────────────────────────┘\n");
		}
	}
	return 0;
}
