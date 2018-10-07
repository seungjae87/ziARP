///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name		: op_list.cpp
//	* Author		: 이승재-(Seungjae Lee)
//	* Date			: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		 ARP REQUEST, ARP REPLY 패킷에 대해 Queue에 저장한다.
//		 해당 모듈은 ARP REQUEST, REPLY Queue를 생성, 저장, 갱신하는데 필요한 함수들로
//		 구성되 있다.
//
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
//
//	'#include's
//
///////////////////////////////////////////////////////////////////////////////////////
#include "header/op_list.h"
#include "header/policy.h"
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>

///////////////////////////////////////////////////////////////////////////////////////
//
//	Global Variables
//
///////////////////////////////////////////////////////////////////////////////////////
PARPPKT_L HEADER_REPLY;		// ARP Request Queue header
PARPPKT_L HEADER_REQUEST;	// ARP Reply Queue header

///////////////////////////////////////////////////////////////////////////////////////
//
//	Body
//
///////////////////////////////////////////////////////////////////////////////////////
//=====================================================================================
//
//	* Function : CreateRequest(), CreateReply()
//	* Description 
//		ARP Request, Reply Queue 생성
//
//=====================================================================================
PARPPKT_L createRequest(PARPPKT_L h, unsigned char* addr)
{
	PARPPKT_L node = (ARPPKT_L*)malloc(sizeof(ARPPKT_L));
	node->next = NULL;
	memcpy( node->arpData.tpa , addr, IP_ALEN);
	return node;
}
PARPPKT_L createReply(PARPPKT_L h, unsigned char* haddr, unsigned char* paddr)
{
	PARPPKT_L node = (ARPPKT_L*)malloc(sizeof(ARPPKT_L));
	node->next = NULL;
	node->ref = 1;
	memcpy( node->arpData.sha , haddr,ETH_ALEN);
	memcpy( node->arpData.spa, paddr,IP_ALEN);
	return node;
}

//=====================================================================================
//
//	* Function : isRequest(), isReply()
//	* Description 
//		ARP Request, Reply Queue에 해당 아이피가 존재하는지 여부를 리턴한다.
//		Input: Header, ip address
//		Output: 1(Exist), 0(or not)
//
//=====================================================================================
int isRequest(PARPPKT_L h, unsigned char* addr)
{
	PARPPKT_L p;
	int i=0;
	if(h==NULL) return 0;
	for( p=h ; p != NULL; p = p->next){
		if( memcmp(p->arpData.tpa, addr, IP_ALEN) == 0 ) // exist
			return 1;
	}
	return 0;
}
int isReplyExist(PARPPKT_L h, unsigned char* addr)
{
	PARPPKT_L p;
	if(h==NULL) return 0;
	for( p=h ; p != NULL; p = p->next){
		if( memcmp(p->arpData.spa, addr, IP_ALEN) == 0 ) // exist
			return 1;
	}
	return 0;
}

//=====================================================================================
//
//	* Function : addRequest, addReply
//	* Description 
//		해당 아이피를 queue에 추가한다.
//
//=====================================================================================
void addRequest(PARPPKT_L h, unsigned char* addr)
{
	if(h==NULL){ // 초기 생성
		PARPPKT_L temp = createRequest(h, addr);
		HEADER_REQUEST = temp;
		return;
	}

	PARPPKT_L temp = (ARPPKT_L*)malloc(sizeof(ARPPKT_L));
	memcpy( temp->arpData.tpa, addr, IP_ALEN);
	temp->next = NULL;
	PARPPKT_L p = h;
	while(p->next != NULL){
		p = p->next;
	}
	p->next = temp;
}
void addReply(PARPPKT_L h, unsigned char* haddr, unsigned char* paddr)
{
	if(h==NULL){ // 초기 생성
		PARPPKT_L temp = createReply(h,haddr,paddr);
		HEADER_REPLY = temp;
		return;
	}

	PARPPKT_L temp = (ARPPKT_L*)malloc(sizeof(ARPPKT_L));
	memcpy(temp->arpData.sha, haddr, ETH_ALEN);
	memcpy(temp->arpData.spa, paddr, IP_ALEN);
	temp->ref = 1;
	temp->next = NULL;
	PARPPKT_L p = h;
	while(p->next != NULL){
		p = p->next;
	}
	p->next = temp;
}


//=====================================================================================
//
//	* Function : updateReply()
//	* Description 
//		정상적인 arp 과정은 이전에 request가 존재할 경우 reply가 날라온다.
//		해당 함수는 이전에 request가 존재하지 않았을 경우 호출된다.
//		updateReply 호출시 해당 ip주소에 대해 ref값을 1만큼 증가시킨다.
//		그 후 policy.h에 정의되 있는 정책에 따라 리턴값이 정해진다.
//		만일 ref값이 ATTACK_COUNT_POLICY 이상일 경우 2를 리턴하고
//		SUSPICIUS_COUNT_POLICY 이상일 경우 1을 리턴하고.
//		그렇지 않을 경우는 0을 리턴한다. 
//		이 함수가 리턴하는 값에 따라 해당 Reply packet의 의심, 공격, 정상 패킷 여부를 판단한다.
//
//=====================================================================================
int updateReply(PARPPKT_L h, unsigned char* addr)
{
	PARPPKT_L p = h;

	while(p!=NULL && memcmp(p->arpData.spa, addr, IP_ALEN)!=0 ){
		p = p->next;
	}

	// 해당 ip존재
	if(p!=NULL) 
		p->ref++;

	// ref값 증가
	if( p->ref >= ATTACK_COUNT_POLICY )
		return 2;	//ATTACK
	else if( p->ref >= SUSPICIUS_COUNT_POLICY)
		return 1;	//SUSPICIOUS
	return 0;		//NOMAL
}

//=====================================================================================
//
//	* Function : deleteRequest(), deleteReply()
//	* Description 
//		해당 아이피 주소에 해당하는 node를 queue에서 삭제한다.
//
//=====================================================================================
void deleteRequest(PARPPKT_L h, unsigned char* addr)
{
	PARPPKT_L p = h;
	PARPPKT_L temp;
	if(memcmp(p->arpData.tpa, addr, IP_ALEN) == 0){ // 첫째 node가 해당 ip일경우
		temp = HEADER_REQUEST;
		HEADER_REQUEST = HEADER_REQUEST->next;
		free(temp);
		return;
	}
	while( p->next != NULL && memcmp( p->next->arpData.tpa, addr, IP_ALEN)!=0){
		p = p->next;
	}
	if(p->next != NULL){
		temp = p->next;
		p->next = p->next->next;
		free(temp);
	}
}
void deleteReply(PARPPKT_L h, unsigned char* addr)
{
	PARPPKT_L p = h;
	PARPPKT_L temp;
	if(memcmp(p->arpData.spa, addr, IP_ALEN) == 0){
		temp = HEADER_REPLY;
		HEADER_REPLY = HEADER_REPLY->next;
		free(temp);
		return;
	}
	while( p->next != NULL && memcmp(p->next->arpData.spa, addr, IP_ALEN)!=0){ // 첫째 node가 해당 ip일경우
		p = p->next;
	}
	if(p->next != NULL){
		temp = p->next;
		p->next = p->next->next;
		free(temp);
	}
}
