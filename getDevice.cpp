///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name		: getDevice.cpp
//	* Author		: 이승재-(Seungjae Lee)
//	* Date			: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		winpcap을 이용하여 해당 컴퓨터의 디바이스 리스트를 가지고 오고 
//		링크드 리스트에 추가하는 모듈을 담고있다.
//
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
//
//	'#include's
//
///////////////////////////////////////////////////////////////////////////////////////
#define HAVE_REMOTE
#include "header/datas.h"
#include "header/get_info.h"
#include "header/log.h"

///////////////////////////////////////////////////////////////////////////////////////
//
//	Prototypes
//
///////////////////////////////////////////////////////////////////////////////////////
void addDevice(PDEVICE_L h, char* deviceName, char* desc);
void getDevice();


///////////////////////////////////////////////////////////////////////////////////////
//
//	Body
//
///////////////////////////////////////////////////////////////////////////////////////
//=====================================================================================
//
//	* Function : getDevice()
//	* Description 
//		사용자 시스템에 활성화된 인터페이스를 가지고 오고 해당 정보를 링크드 리스트에 저장한다.
//
//=====================================================================================
void getDevice() {
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* 현재 컴퓨터의 네트워크 디바이스 리스트 얻어오기 */
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		log("[Error] Error in pcap_findalldevs");
		exit(1);
	}
	
	/* Device 정보 저장 */
	for(d = alldevs, i=0; d; d = d->next, i++){
		addDevice(deviceList,d->name, d->description);
	}
	/* 디바이스 리스트가 존재하지 않음. winpcap이 설치되지 않았을 경우도 있다. */
	if(i == 0){
		log("[Error] No interfaces found! Make sure WinPcap is installed.");
		SendMessage(hC1, WM_SPOOF, SM_NODEVICE, NULL);
		return;
	}
}
//=====================================================================================
//
//	* Function : addDevice
//	* Description 
//		GUI에 보여줄 인터페이스 리스트는 deviceList헤더에 저장된다.
//		addDevice는 getDevice함수에서 사용되며 deviceList헤더에 인터페이스를 추가하는 함수다.
//
//=====================================================================================
void addDevice(PDEVICE_L h, char* deviceName, char* desc)
{
	PDEVICE_L p;
	unsigned char ipAddr[IP_ALEN];
	unsigned char macAddr[ETH_ALEN];
	unsigned char netmask[IP_ALEN];

	get_info(deviceName,macAddr,ipAddr,netmask);

	if(h==NULL){
		deviceList = (PDEVICE_L)malloc(sizeof(DEVICE_L));
		deviceList->next = NULL;
		strcpy(deviceList->deviceName, deviceName);
		memcpy(deviceList->ipAddr, ipAddr,IP_ALEN);
		strcpy(deviceList->desc, desc);
	}
	else{
		p=h;
		while(p->next!=NULL){
			p = p->next;
		}
		PDEVICE_L temp = (PDEVICE_L)malloc(sizeof(DEVICE_L));
		temp->next=NULL;
		strcpy(temp->deviceName, deviceName);
		memcpy(temp->ipAddr, ipAddr,IP_ALEN);
		strcpy(temp->desc, desc);
		p->next = temp;
	}
}