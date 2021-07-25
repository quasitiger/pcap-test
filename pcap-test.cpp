#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#include<iostream>
#include<stdio.h>

#include"libnet.h"




void Parse_Ethernet(const u_char * _packet);
void Parse_IPv4(const u_char * _packet);
void Parse_IPv6(const u_char * _packet);
void Parse_ARP(const u_char * _packet);
void Parse_TCP(const u_char * _packet);
void Parse_UDP(const u_char * _packet);


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
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

int main(int argc, char* argv[]) 
{
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

	if (pcap == NULL) 
	{
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) 
	{
		
		struct pcap_pkthdr* header;
		const u_char* packet;

		
		

		int res = pcap_next_ex(pcap, &header, &packet);

		

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
	
		Parse_Ethernet(packet);


	}

	pcap_close(pcap);
}

void Parse_Ethernet(const u_char * _packet)
{

	
	// pointer inverse referensing
	//test2 * id = (test2*)ic;
	
	//uint8_t* pd = id->a;
	// std::cout << "pd[i] : " << pd[i] << std::endl;
	// std::cout << "(*pd) : " << (*pd)++ << std::endl;

	//uint8_t pd2 = *id->a;
	// std::cout << "(&pd2)[i] : " << (*(&pd2))++ << std::endl;
	// std::cout << "(&pd2)[i] : " << (&pd2)[0]++ << std::endl;
	
	
	  //ㅇ 0600h      Xerox XNS IDP
	  //ㅇ 0800h      IPv4
	  //ㅇ 0805h      X.25
	  //ㅇ 0806h      ARP
	  //ㅇ 0835h      RARP
	  //ㅇ 6003h      DEC DECnet Phase Ⅳ
	  //ㅇ 8100h      VLAN ID
	  //ㅇ 8137h      Novell Netware IPX
	  //ㅇ 8191h      NetBIOS 
	  //ㅇ 86DDh      IPv6
	  //ㅇ 8847h      MPLS  
	  //ㅇ 8863h      PPPoE Discovery Stage 
	  //ㅇ 8864h      PPPoE PPP Session Stage
	  //ㅇ 888Eh      IEEE 802.1X
	  //ㅇ 88CCh      LLDP (Link Layer Discovery Protocol)
	  
	// IPv4 : 0x0800, IPv6 : 86DD, ARP : 0x08총 11개 나왔습니다06
	
	printf( "    \n================================\n");
	printf( " Packet Parse Start\n\n");
	
	// is the direct access pcap data impossible?
	//pcap_t * pcap = *_pcap+24;
	struct libnet_ethernet_hdr * parse = (struct libnet_ethernet_hdr*)(_packet);
	
	uint16_t ether_type;
	
	// ntohs : network to host
	// htons, htonl : host to network
	ether_type = ntohs(parse -> ether_type  );
	
	

	//printf(" ether_type : %04X \n", ether_type);
		
	// print dst mac address
	printf( " MAC dst : %02X:%02X:%02X:%02X:%02X:%02X\n",
	parse->ether_dhost[0],
	parse->ether_dhost[1],
	parse->ether_dhost[2],
	parse->ether_dhost[3],
	parse->ether_dhost[4],
	parse->ether_dhost[5]);	
	
	// print src mac address
	printf( " MAC src : %02X:%02X:%02X:%02X:%02X:%02X\n\n",
	parse->ether_shost[0],
	parse->ether_shost[1],
	parse->ether_shost[2],
	parse->ether_shost[3],
	parse->ether_shost[4],
	parse->ether_shost[5]);	
	
	
	// IPv4
	if( ether_type == 0x0800)
	{	
		printf( " ================================\n ");
		printf( "IPv4 packet Detected\n");
		Parse_IPv4( _packet + sizeof(struct libnet_ethernet_hdr) );
	}
	//IPv6
	else if ( ether_type == 0x86DD)
	{
		printf( " ================================\n ");
		printf( " IPv6 packet Detected\n");
		Parse_IPv6( _packet + sizeof(struct libnet_ethernet_hdr) );
		
		//Parse_IPv6()
	}
	// ARP
	else if ( ether_type == 0x0806)
	{
		printf( " ================================\n ");
		printf( " ARP packet Detected\n");	
		Parse_ARP( _packet + sizeof(struct libnet_ethernet_hdr) );
		//Parse_ARP()
	}
	// Another
	else
	{
		printf( " ================================\n ");
		printf( " ETC.. packet Detected\n");
	}
	
	
	printf( " \n\n Packet Parse End\n");
	printf( " ================================\n\n ");
	



}


void Parse_IPv4(const u_char * _packet)
{
	//printf("ipv4 in");
	struct libnet_ipv4_hdr * parse = (struct libnet_ipv4_hdr*)(_packet);
	

	uint32_t src_IP = parse->ip_src.s_addr;
	uint32_t dst_IP = parse->ip_dst.s_addr;
	    
	uint8_t temp[4];
	temp[3] = ( src_IP >> 24 ) & 0xFF;
	temp[2] = ( src_IP >> 16 ) & 0xFF;
	temp[1] = ( src_IP >> 8 ) & 0xFF;
	temp[0] = src_IP & 0xFF;
	printf(" src IP : ");
	for(int i = 0; i < 4; i++)
	{
		printf(" %d", temp[i]);
		if( i != 3) 
			printf(".");
	}
	printf("\n");

	temp[3] = ( dst_IP >> 24 ) & 0xFF;
	temp[2] = ( dst_IP >> 16 ) & 0xFF;
	temp[1] = ( dst_IP >> 8 ) & 0xFF;
	temp[0] = dst_IP & 0xFF;
	printf(" dst IP : ");
	for(int i = 0; i < 4; i++)
	{
		printf(" %d", temp[i]);
		if( i != 3)
			printf(".");
	}
	printf("\n");
	
	//uint8_t protocol = ntohs(parse->ip_p);
	//printf(" protocol : %04X \n", parse->ip_p);
	//printf(" protocol : %04X \n", protocol);
	
	if ( parse->ip_p == 0x06 )
	{
		printf("\n TCP detected\n");
		Parse_TCP(_packet + sizeof(struct libnet_ipv4_hdr));
	}
	else if ( parse->ip_p == 0x11)
	{
		printf("\n UDP detected\n");
		Parse_UDP(_packet + sizeof(struct libnet_ipv4_hdr));
	}
	
	
	
	//unsigned int src_IP = inet_addr(inet_ntoa(parse->ip_src.s_addr));
	//unsigned int dst_IP = inet_addr(inet_ntoa(parse->ip_dst.s_addr));

//	unsigned int src_IP = inet_addr(inet_ntoa(parse->ip_src.s_addr));
//	unsigned int dst_IP = inet_addr(inet_ntoa(parse->ip_dst.s_addr));

  //  	printf("Src IP  : %s\n", inet_ntoa(src_IP) );

    //    printf("Dst IP  : %s\n", inet_ntoa(dst_IP) );
        
        
        
        
        
        
        
}

void Parse_IPv6(const u_char * _packet)
{
	
	struct libnet_ipv6_hdr * parse = (struct libnet_ipv6_hdr*)(_packet);
	
	//struct libnet_ipv6_hdr
	//{
    	//	u_int8_t ip_flags[4];     /* version, traffic class, flow label */
    	//	u_int16_t ip_len;         /* total length */
   	//	u_int8_t ip_nh;           /* next header */
    	//	u_int8_t ip_hl;           /* hop limit */
    	//	struct libnet_in6_addr ip_src, ip_dst; /* source and dest address */
	//};
	
	//struct libnet_in6_addr
	//{
	//   union
	//    {
	//	u_int8_t   __u6_addr8[16];
	//	u_int16_t  __u6_addr16[8];
	//	u_int32_t  __u6_addr32[4];
	//   } __u6_addr;            /* 128-bit IP6 address */
	//};
	
	// 2byte 2byte
	
	uint32_t * ip_8 = parse->ip_src.__u6_addr.__u6_addr32;
	uint16_t * ip_4 = parse->ip_src.__u6_addr.__u6_addr16;
	uint8_t * ip_2 = parse->ip_src.__u6_addr.__u6_addr8;
	
	
	for(int i = 0; i < sizeof(libnet_in6_addr)/sizeof(uint16_t); i++)
	{
		printf("%X ", (ip_8)[i]);
	}
}	
	
	
void Parse_ARP(const u_char * _packet)
{
	
	struct libnet_arp_hdr * parse = (struct libnet_arp_hdr*)(_packet);
	
	
	
}

void Parse_TCP(const u_char * _packet)
{
	
	struct libnet_tcp_hdr * parse = (struct libnet_tcp_hdr*)(_packet);
	
	uint16_t src_port = parse->th_sport;
	uint16_t dst_port = parse->th_dport;
	
	printf(" src port : %d\n", src_port);
	printf(" dst port : %d\n", dst_port);
	
	// data print
	
	unsigned char * data = (unsigned char *)(parse + sizeof(struct libnet_tcp_hdr));
	typedef  unsigned char* uchar;
	uchar p_data = data;
	
	for(int i = 0; i < 8; i++)
	{
		if (p_data == NULL)
			break;
			
		printf(" %02X ", p_data[i]);
	} 
}


void Parse_UDP(const u_char * _packet)
{
	
	struct libnet_udp_hdr * parse = (struct libnet_udp_hdr*)(_packet);
	

	uint16_t src_port = parse->uh_sport;
	uint16_t dst_port = parse->uh_dport;
	
	printf(" src port : %d\n", src_port);
	printf(" dst port : %d\n", dst_port);
	
	unsigned char * data = (unsigned char *)(parse + sizeof(struct libnet_udp_hdr));
	typedef  unsigned char* uchar;
	uchar p_data = data;
	
	for(int i = 0; i < 8; i++)
	{
		if (p_data == NULL)
			break;
			
		printf(" %02X ", p_data[i]);
	} 
		
}



