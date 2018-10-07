///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name		: openDevice.cpp
//	* Author		: 이승재-(Seungjae Lee)
//					  김민우-(Minwoo Kim)
//					  최서율-(Seoyul Choi)
//	* Date			: 2012. 7. 16 - 2012. 8. 4
//
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
//
//	'#include's
//
///////////////////////////////////////////////////////////////////////////////////////
#define HAVE_REMOTE
#include "header/datas.h"
#include "header/policy.h"
#include "header/log.h"
#include <pcap.h>
#include <memory.h>

#define PACKET_SIZE 42
void CharToTCHAR(char* char_str, TCHAR* TCHAR_str);
///////////////////////////////////////////////////////////////////////////////////////
//
//	Body
//
///////////////////////////////////////////////////////////////////////////////////////
//=====================================================================================
//
//	* Function : openDevice()
//	* Description
//		 해당 모듈은 사용자가 선택한 디바이스를 열고 해당 핸들을 datas.cpp에 선언된
//		adhandle에 저장한다.
//
//=====================================================================================
int openDevice(int index){

	char errbuf[PCAP_ERRBUF_SIZE];
	int counter;
	char logmsg[LOG_MSG_SIZE];
	unsigned int lNetMask = 0;
	struct bpf_program lFCode;

	for(d=alldevs, counter=0; d; d=d->next, counter++){
		if(counter==index){
			strncpy(deviceName,d->name,1024);
			break;
		}
	}

	/* 디바이스 열기 */
	if((adhandle = pcap_open(deviceName, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL){
		sprintf(logmsg,"[Error] Unable to open the adapter. not supported by WinPcap\n");
		log(logmsg);
		SendMessage(hC1, WM_SPOOF, SM_NODEVICE, NULL);
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		lNetMask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		lNetMask = 0xffffff;

	ZeroMemory(&lFCode, sizeof(lFCode));
	if(pcap_compile(adhandle, &lFCode, "", 1, lNetMask) < 0 ) {
		log("[Error] Unable to compile the packet filter. \n");
		exit(1);
	}

	if(pcap_setfilter(adhandle, &lFCode) < 0 ) {
		log("[Error] Error setting the filter.\n");
	}

	/* 로그기록 */
	sprintf(logmsg, "[Info] %s Device Opened\n\r", d->description);
	log(logmsg);
	/* 네트워크 디바이스 목록 해제 */
	pcap_freealldevs(alldevs);
	return 0;
}