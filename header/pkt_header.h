///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name	: pkt_header.h
//	* Author	: 이승재(Seunjae Lee)
//	* Date		: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		 이더넷과 ARP 헤더에 대한 구조체를 정의한다.
//
///////////////////////////////////////////////////////////////////////////////////////
#ifndef __PKT_HEADER_H__
#define __PKT_HEADER_H__
///////////////////////////////////////////////////////////////////////////////////////
//
//	'#define's and other preprocessing codes
//
///////////////////////////////////////////////////////////////////////////////////////
#define ETH_ALEN	6
#define IP_ALEN		4
#define ARP_REQUEST 1
#define ARP_REPLY	2

///////////////////////////////////////////////////////////////////////////////////////
//
//	'typedef's
//
///////////////////////////////////////////////////////////////////////////////////////
typedef struct ethern_hdr {
	unsigned char	ether_dhost[ETH_ALEN];	// dest Ethernet address
	unsigned char	ether_shost[ETH_ALEN];	// source Ethernet address
	unsigned short	ether_type;				// protocol (16-bit)
} ETHDR, *PETHDR;

typedef struct arphdr {
	unsigned short	htype;	// format of hardware address
	unsigned short	ptype;	// format of protocol address
	unsigned char	hlen;	// length of hardware address
	unsigned char	plen;	// length of protocol address
	unsigned short	opcode;	// ARP/RARP operation
	unsigned char	sha[ETH_ALEN];	// sender hardware address
	unsigned char	spa[IP_ALEN];	// sender protocol address
	unsigned char	tha[ETH_ALEN];	// target hardware address
	unsigned char	tpa[IP_ALEN];	// target protocol address
	unsigned char	hostname[16];
} ARPHDR, *PARPHDR;
#endif


