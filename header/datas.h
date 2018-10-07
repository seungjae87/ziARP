///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name		: datas.h
//	* Author		: 이승재-(Seungjae Lee)
//	* Date			: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		 탐지 엔진 모듈에서 필요한 변수를 선언하고 해당 구조체 타입에 대한 정의를 한다.
//	주로 자신의 네트워크 환경정보와 탐지에 사용되는 interface의 정보들을 정의하고 있다.
//  datas.cpp에 있는 변수를 사용하기 위해서는 해당 헤드를 include시켜야 한다.
//
///////////////////////////////////////////////////////////////////////////////////////
#ifndef __GLOBAL__
#define __GLOBAL__
///////////////////////////////////////////////////////////////////////////////////////
//
//	'#include's
//
///////////////////////////////////////////////////////////////////////////////////////
#include <pcap.h>
#include "spoof_list.h"
///////////////////////////////////////////////////////////////////////////////////////
//
//	'#define's and other preprocessing codes
//	 SendMessage에 사용될 메시지 타입을 정의
//
///////////////////////////////////////////////////////////////////////////////////////
#define STRSIZE 100
#define WM_SPOOF (WM_USER+1)
#define SM_INIT 0
#define SM_ADD 1
#define SM_CHANGE 2
#define SM_STOP_THREAD 3
#define SM_RESUME_THREAD 4
#define SM_NODEVICE 40
#define SM_UPDATE_HOSTNAME		50
#define SM_UPDATE_LIST_NOMAL	51
#define SM_UPDATE_LIST_SUSP		52
#define SM_UPDATE_LIST_ATTACK	53
#define SM_UPDATE_LIST_STATIC	54

///////////////////////////////////////////////////////////////////////////////////////
//
//	'typedef's
//
///////////////////////////////////////////////////////////////////////////////////////
// 인터페이스의 정보를 담는 리스트
typedef struct DEVICE_L {
	DEVICE_L* next;
	char deviceName[STRSIZE];
	unsigned char ipAddr[IP_ALEN];
	char desc[STRSIZE];
} DEVICE_L, *PDEVICE_L;

// 상태변경을 알릴때(updateState())에 사용될 구조체
typedef struct ARPDATA {
	unsigned char ipAddr[IP_ALEN];
	unsigned char macAddr[ETH_ALEN];
	char vendor[36];
	char timestr[50];
} ARPDATA;

///////////////////////////////////////////////////////////////////////////////////////
//
//	Global Variables
//
///////////////////////////////////////////////////////////////////////////////////////
extern struct sockaddr *addr;
extern struct sockaddr_in *in;

// 자신의 네트워크 환경 정보
extern unsigned char myIPaddr[IP_ALEN];
extern unsigned char if_mac[ETH_ALEN];
extern unsigned char netmask[IP_ALEN];
extern unsigned char myNetID[IP_ALEN];
extern char buff[512];

// GUI 우측 리스트에 출력되는 정보를 담고있는 링크드 리스트 헤더
extern PSPOOF_L ARP_LIST;

// Winpcap을 이용하여 패킷을 송수신할 핸들
extern pcap_t *adhandle;

// Winpcap을 이용하여 사용할 인터페이스 디바이스 이름
extern char deviceName[];

// Winpcap을 이용하여 추출한 모든 인터페이스 리스트
extern pcap_if_t *alldevs;
// 선택한 인터페이스 노드
extern pcap_if_t *d;

// 현재 사용자 컴퓨터의 인터페이스 목록을 담고있는 링크드 리스트
extern PDEVICE_L deviceList;

// 상태(정상,경고,위험,정적)의 변화를 알릴 때(updateState함수 <spoof_list.cpp>) 해당 정보를 담는 변수
extern ARPDATA ARP_DATA;

// GUI의 윈도우 핸들
extern HWND hC1;
#endif

