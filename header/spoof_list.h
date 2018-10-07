///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name	: spoof_list.h
//	* Author	: 이승재(Seunjae Lee)
//	* Date		: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		 SPOOF_L 구조체 타입을 정의하고 spoof_list 모듈을 사용하기 위한 헤더파일이다.
//
///////////////////////////////////////////////////////////////////////////////////////

#ifndef __SPOOF_LIST_H__
#define __SPOOF_LIST_H__
///////////////////////////////////////////////////////////////////////////////////////
//
//	'#include's
//
///////////////////////////////////////////////////////////////////////////////////////
#include "header/arp_LinkedList.h"

///////////////////////////////////////////////////////////////////////////////////////
//
//	'#defines
//	 flag값 정의
//
///////////////////////////////////////////////////////////////////////////////////////
#define STATIC			3
#define ATTACK			2
#define SUSPICIOUS		1
#define NOMAL			0

#define HOST_STR_SIZE		17
#define TIME_STR_SIZE		50
#define VENDOR_STR_SIZE		36
///////////////////////////////////////////////////////////////////////////////////////
//
//	'typedef's
//
///////////////////////////////////////////////////////////////////////////////////////
typedef struct SPOOF_L {
	SPOOF_L*		next;
	char	flag;
	unsigned char	ipAddr[IP_ALEN];
	unsigned char	macAddr[ETH_ALEN];
	char	vendor[VENDOR_STR_SIZE];
	char	timestr[TIME_STR_SIZE];
	char	hostName[HOST_STR_SIZE];
} SPOOF_L, *PSPOOF_L;

///////////////////////////////////////////////////////////////////////////////////////
//
//	Prototypes
//
///////////////////////////////////////////////////////////////////////////////////////
PSPOOF_L createSpoof(PSPOOF_L h, char flag, unsigned char* ipAddr, unsigned char* macAddr, 
					char* vendor, char* timestr, char* hostName);
int isSpoof(PSPOOF_L h, unsigned char* ipAddr);
void addSpoof(PSPOOF_L h, char flag, unsigned char* ipAddr, unsigned char* macAddr, 
					char* vendor, char* timestr, char* hostName);
void deleteSpoof(PSPOOF_L h, unsigned char* ipAddr, char status);
void updateSpoof(PSPOOF_L h, unsigned char* ipAddr, char* timestr);
int isEmptySpoof(PSPOOF_L h);
void refreshSpoofAttack( char* timestr);
void refreshSpoofSuspicius( char* timestr);
void updateState(PSPOOF_L h, char flag, unsigned char* ipAddr, unsigned char* macAddr, 
			char* vendor, char* timestr, char* hostName);
void add_hostname(PSPOOF_L h, unsigned char* ipAddr, char* hostname);

///////////////////////////////////////////////////////////////////////////////////////
//
//	Global Variables
//
///////////////////////////////////////////////////////////////////////////////////////
extern PSPOOF_L HEADER_ATTACK;
extern PSPOOF_L HEADER_SUSPICIUS;
extern PSPOOF_L HEADER_STATIC;
#endif
