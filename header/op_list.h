///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name	: op_list.h
//	* Author	: 이승재(Seungjae Lee)
//	* Date		: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		ARP Request, ARP Reply 패킷 queue를 다루는 op_list.cpp를 위한
//		Prototype들이 선언되어 있다. op_list 모듈을 사용하기 위해서는 해당 헤더를
//		include 시켜야 한다.
//
///////////////////////////////////////////////////////////////////////////////////////
#ifndef __OP_LIST_H__
#define __OP_LIST_H__
///////////////////////////////////////////////////////////////////////////////////////
//
//	'#include's
//
///////////////////////////////////////////////////////////////////////////////////////
#include "header/arp_LinkedList.h"

///////////////////////////////////////////////////////////////////////////////////////
//
//	Prototypes
//
///////////////////////////////////////////////////////////////////////////////////////
PARPPKT_L createRequest(PARPPKT_L h, unsigned char*);
PARPPKT_L createReply(PARPPKT_L h, unsigned char* haddr, unsigned char* paddr);
int isRequest(PARPPKT_L h, unsigned char*);
int isReplyExist(PARPPKT_L h, unsigned char*);
void addRequest(PARPPKT_L h, unsigned char*);
void addReply(PARPPKT_L h, unsigned char* haddr, unsigned char* paddr);
int updateReply(PARPPKT_L h, unsigned char*);
void deleteRequest(PARPPKT_L h, unsigned char*);
void deleteReply(PARPPKT_L h, unsigned char*);

///////////////////////////////////////////////////////////////////////////////////////
//
//	Global Variables
//
///////////////////////////////////////////////////////////////////////////////////////
extern PARPPKT_L HEADER_REPLY;
extern PARPPKT_L HEADER_REQUEST;
#endif