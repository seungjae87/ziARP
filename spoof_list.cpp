///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name		: spoof_list.cpp
//	* Author		: 이승재-(Seungjae Lee)
//	* Date			: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		 PSPOOF_L 구조체는 GUI 우측창에 출력되는 정보를 가지고 있는 링크드 리스트이다.
//		해당 모듈은 PSPOOF_L 리스트에 필요한 여러 함수들을 가지고 있다.
//		(추가, 삭제, 생성, 업데이트, 갱신)
//		PSPOOF_L 구조체를 사용하는 리스트는 HEADER_ATTACK, HEADER_SUSPICIUS, HEADER_STATIC
//		3가지가 있다.
//		HEADER_ATTACK 공격으로 추정되는 패킷 정보를 유지한다.
//		HEADER_SUSPICIUS 공격으로 의심되는 패킷 정보를 유지한다.
//		HEADER_STATIC	정적으로 설정된 리스트를 유지한다.
//
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
//
//	'#include's
//
///////////////////////////////////////////////////////////////////////////////////////
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
#include <Windows.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include "header/datas.h"
#include "header/spoof_list.h"
#include "header/log.h"
#include "header/policy.h"
#include "header/get_info.h"

///////////////////////////////////////////////////////////////////////////////////////
//
//	Global Variables
//
///////////////////////////////////////////////////////////////////////////////////////
PSPOOF_L HEADER_ATTACK;
PSPOOF_L HEADER_SUSPICIUS;
PSPOOF_L HEADER_STATIC;

///////////////////////////////////////////////////////////////////////////////////////
//
//	Body
//
///////////////////////////////////////////////////////////////////////////////////////
//=====================================================================================
//
//	* Function : createSpoof
//	* Description 
//		리스트를 새로 만들고 넘겨 받은 인자로 내용을 채운다.
//		그 후 해당 노드의 주소를 리턴한다.
//
//=====================================================================================
PSPOOF_L createSpoof(PSPOOF_L h, char flag, unsigned char* ipAddr, unsigned char* macAddr, 
					char* vendor, char* timestr, char* hostName)
{
	PSPOOF_L node = (SPOOF_L*)malloc(sizeof(SPOOF_L));
	node->next = NULL;
	node->flag=flag;
	memcpy(node->ipAddr, ipAddr, IP_ALEN);
	memcpy(node->macAddr, macAddr, ETH_ALEN);
	strcpy(node->vendor, vendor);
	strcpy(node->timestr, timestr);
	strcpy(node->hostName, hostName);
	return node;
}

//=====================================================================================
//
//	* Function : isSpoof
//	* Description 
//		넘겨 받은 헤더의 링크드 리스트에서 특정 아이피값을 가지는 노드가 존재하는지 결과를
//		리턴한다. 존재하면 '1'을 그렇지 않으면 '0'을 리턴한다.
//
//=====================================================================================
int isSpoof(PSPOOF_L h, unsigned char* ipAddr)
{
	PSPOOF_L p;
	int i=0;
	if(h==NULL) return 0;
	for( p=h; p !=NULL ; p=p->next){
		if(memcmp(p->ipAddr, ipAddr, IP_ALEN)==0) //exist
			return 1;
	}
	return 0;
}

//=====================================================================================
//
//	* Function : addSpoof
//	* Description 
//		넘겨받은 flag(ATTACK, SUSPICIUS, NOMAL, STATIC)에 해당하는 리스트에 새로운 노드를
//		추가한다. 기존 리스트가 존재하지 않을 경우 새로 생성한다. 그렇지 않을 경우는 리스트
//		끝에 새로운 노드를 붙여넣는다.
//
//=====================================================================================
void addSpoof(PSPOOF_L h, char flag, unsigned char* ipAddr, unsigned char* macAddr, 
			char* vendor, char* timestr, char* hostName)
{
	// 새로 생성
	if(h==NULL){
		if( flag == ATTACK){
			PSPOOF_L temp = createSpoof(h,ATTACK,ipAddr,macAddr,vendor,timestr,hostName);
			HEADER_ATTACK = temp;
		}
		else if( flag == SUSPICIOUS){
			PSPOOF_L temp = createSpoof(h,SUSPICIOUS,ipAddr,macAddr,vendor,timestr,hostName);
			HEADER_SUSPICIUS = temp;
		}
		else if( flag == NOMAL) {
			PSPOOF_L temp = createSpoof(h,NOMAL,ipAddr,macAddr,vendor,timestr,hostName);
			ARP_LIST = temp;
		}
		else if( flag == STATIC) {
			PSPOOF_L temp = createSpoof(h,STATIC,ipAddr,macAddr,vendor,timestr,hostName);
			HEADER_STATIC = temp;
		}
		return;
	}

	// 기존 리스트 뒤에 붙인다.
	PSPOOF_L temp = (SPOOF_L*)malloc(sizeof(SPOOF_L));
	temp->next = NULL;
	temp->flag=flag;
	memcpy(temp->ipAddr, ipAddr, IP_ALEN);
	memcpy(temp->macAddr, macAddr, ETH_ALEN);
	strcpy(temp->vendor, vendor);
	strcpy(temp->timestr, timestr);
	strcpy(temp->hostName, hostName);

	// 링크드 리스트의 끝으로 이동
	PSPOOF_L p = h;
	while(p->next != NULL){
		p = p->next;
	}
	p->next = temp;
}

//=====================================================================================
//
//	* Function : updateSpoof
//	* Description 
//		넘겨받은 ip 주소에 해당하는 노드의 시간을 업데이트한다.
//
//=====================================================================================
void updateSpoof(PSPOOF_L h, unsigned char* ipAddr, char* timestr)
{
	PSPOOF_L p = h;
	while(p!=NULL && memcmp(p->ipAddr, ipAddr, IP_ALEN)!=0){
		p = p->next;
	}
	if(p!=NULL){ // match
		strcpy(p->timestr, timestr);
	//	log("[Debugging] 공격시간 Update ");
	}
}

//=====================================================================================
//
//	* Function : deleteSpoof
//	* Description 
//		해당 ip 주소를 리스트에서 삭제한다.
//
//=====================================================================================
void deleteSpoof(PSPOOF_L h, unsigned char* ipAddr, char flag)
{
	PSPOOF_L p = h;
	PSPOOF_L temp;
	// 첫번째 노드(헤더)와 일치할 경우
	if(memcmp(p->ipAddr,ipAddr,IP_ALEN) == 0){
		if(flag == ATTACK){
			temp = HEADER_ATTACK;
			HEADER_ATTACK = HEADER_ATTACK->next;
		}
		else if(flag == SUSPICIOUS){
			temp = HEADER_SUSPICIUS;
			HEADER_SUSPICIUS = HEADER_SUSPICIUS->next;
		}
		else if(flag == NOMAL){
			temp = ARP_LIST;
			ARP_LIST = ARP_LIST->next;
		}
		free(temp);
		return;
	}
	
	while(p->next !=NULL && memcmp(p->next->ipAddr,ipAddr,IP_ALEN)!=0 ) {
		p = p->next;
	}

	if(p->next != NULL){
		temp = p->next;
		p->next = p->next->next;
		free(temp);
	}
}

//=====================================================================================
//
//	* Function : isEmptySpoof
//	* Description 
//		해당 리스트가 비어있는지 체크
//
//=====================================================================================
int isEmptySpoof(PSPOOF_L h)
{
	if(h==NULL)
		return 1;
	else return 0;
}

//=====================================================================================
//
//	* Function : refreshSpoofAttack, refreshSpoofSuspicius
//	* Description 
//		arpProc함수에 의해 호출되는 함수다. 이 함수는 공격이 멈춤 여부를 체크하고 그 결과를
//		반영한다. 리스트의 각 노드에는 시간이 저장되어 있는데 이시간과 인자로 전달된 시간과
//		비교하여 공격이 멈추었는지를 판단한다. 만일 공격이 멈추었다고 판단되었을 시에는
//		deleteSpoof함수를 호출하여 해당 노드를 삭제하고 윈도우에 Message를 보냄으로 현상황을
//		반영한다.
//
//=====================================================================================
void refreshSpoofAttack(char* timestr)
{
	PSPOOF_L p;
	for(p=HEADER_ATTACK; p ; p = p->next){
		if( strcmp( timestr , p->timestr) > 0 ){ // time over
			unsigned char ipAddr[IP_ALEN];
			memcpy(ipAddr,p->ipAddr,IP_ALEN);

			/*리스트에서 삭제*/
			deleteSpoof(HEADER_ATTACK, ipAddr, ATTACK);
			deleteSpoof(ARP_LIST, ipAddr, NOMAL);

			/*GUI에 알림*/
			SendMessage(hC1, WM_SPOOF, SM_INIT, (LPARAM)ARP_LIST);

			/*로그 기록*/
			char message[LOG_MSG_SIZE];
			sprintf(message, "[Info] spoofed packet stoped. chage state from attack to nomal. TargetIP: %d.%d.%d.%d "
				,ipAddr[0],ipAddr[1],ipAddr[2],ipAddr[3]);	
			log(message);
			break;
		}
	}
}

void refreshSpoofSuspicius(char* timestr)
{
	PSPOOF_L p;
	for(p=HEADER_SUSPICIUS; p; p=p->next){
		if( strcmp( timestr , p->timestr) > 0 ){ // time over
			unsigned char ipAddr[IP_ALEN];
			memcpy(ipAddr,p->ipAddr,IP_ALEN);		

			/*리스트에서 삭제*/
			deleteSpoof(HEADER_SUSPICIUS, ipAddr, SUSPICIOUS);
			deleteSpoof(ARP_LIST,ipAddr, NOMAL);		

			/*GUI에 알림*/
			SendMessage(hC1, WM_SPOOF, SM_INIT, (LPARAM)ARP_LIST);

			/*로그 기록*/
			char message[LOG_MSG_SIZE];
			sprintf(message,"[Info] unrequested reply packet stoped. delete from the Suspicious list. TargetIP: %d.%d.%d.%d"
				,ipAddr[0],ipAddr[1],ipAddr[2],ipAddr[3]);
			log(message);
			break;
		}
	}
}

//=====================================================================================
//
//	* Function : updateState
//	* Description 
//		상태변화(ex 공격->정상, 정상->의심, 의심->공격, 공격->정적)이 발생할 경우 
//		그 내용을 노드에 반영하고 윈도우에 변화가 발생했음을 알리는 메시지를 보낸다.
//		메시지는 SM_CHANGE와 SM_ADD 두가지가 있다. SM_CHANGE는 기존 리스트에 해당 정보가
//		이미 존재하고 상태변화만 발생했을 경우이고 SM_ADD는 기존리스트에 해당 정보가 없을
//		경우 보내는 메시지다. 두 메시지 모두 동일하게 해당 노드의 파라미터를 인자로 보낸다.
//
//=====================================================================================
void updateState(PSPOOF_L h, char flag, unsigned char* ipAddr, unsigned char* macAddr, 
			char* vendor, char* timestr, char* hostName)
{
	PSPOOF_L p = h;
	if( isSpoof(h, ipAddr) ){ //exist
		while(p!=NULL && memcmp(p->ipAddr, ipAddr, IP_ALEN)!=0){
			p = p->next;
		}
		if(p!=NULL){ // match
			p->flag = flag;
			memcpy(p->macAddr,macAddr,ETH_ALEN);
			strcpy(p->timestr,timestr);
			strcpy(p->vendor, vendor);
		}
		/*메시지 발생*/
		if(flag==STATIC) log("[Info] Static update in updateState");
		SendMessage(hC1, WM_SPOOF, SM_CHANGE, (LPARAM)p);
	}
	else { // not exist
		addSpoof(h, flag, ipAddr, macAddr, vendor, timestr, hostName);
		while(p->next != NULL){
			p = p->next;
		}
		
		SendMessage(hC1, WM_SPOOF, SM_ADD, (LPARAM)p);
	}
}

//=====================================================================================
//
//	* Function : add_hostname
//	* Description 
//		add_hostname은 해당 아이피 주소에 대한 호스트네임을 리스트에 반영하는 함수이다.
//
//=====================================================================================
void add_hostname(PSPOOF_L h, unsigned char* ipAddr, char* hostname){

	PSPOOF_L p ;

	for( p=h; p ; p=p->next){
		if(memcmp(p->ipAddr, ipAddr, IP_ALEN)==0)
			memcpy(p->hostName, hostname, 17);
	}

}
