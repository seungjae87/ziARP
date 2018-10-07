///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name		: datas.cpp
//	* Author		: 이승재-(Seungjae Lee)
//	* Date			: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		 탐지 엔진 모듈에서 필요한 변수들을 가지고 있는 파일이다. 
//		 주로 자신의 네트워크 환경정보와 탐지에 사용되는 interface의 정보들을 정의하고 있으며
//		 GUI 모듈에서 출력될 정보들의 링크드 리스트의 헤더들이 들어있다.
//
///////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////
//
//	'#include's
//
///////////////////////////////////////////////////////////////////////////////////////
#include "header/datas.h"

///////////////////////////////////////////////////////////////////////////////////////
//
//	#defines
//
///////////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////////////
//
//	Global Variables
//
///////////////////////////////////////////////////////////////////////////////////////
struct sockaddr *addr;
struct sockaddr_in *in;

// 자신의 네트워크 환경 정보
unsigned char myIPaddr[IP_ALEN];
unsigned char if_mac[ETH_ALEN];
unsigned char netmask[IP_ALEN];
unsigned char myNetID[IP_ALEN];
char buff[512];

// GUI 우측 리스트에 출력되는 정보를 담고있는 링크드 리스트 헤더
PSPOOF_L ARP_LIST;

// Winpcap을 이용하여 패킷을 송수신할 핸들
pcap_t *adhandle;

// Winpcap을 이용하여 사용할 인터페이스 디바이스 이름
char deviceName[1024];

// Winpcap을 이용하여 추출한 모든 인터페이스 리스트
pcap_if_t *alldevs;
// 선택한 인터페이스 노드
pcap_if_t *d;

// 현재 사용자 컴퓨터의 인터페이스 목록을 담고있는 링크드 리스트
PDEVICE_L deviceList = NULL;

// 상태(정상,경고,위험,정적)의 변화를 알릴 때(updateState함수 <spoof_list.cpp>) 해당 정보를 담는 변수
ARPDATA ARP_DATA;
