///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name		: detect_engin.cpp
//	* Author		: 이승재-(Seungjae Lee)
//	* Date			: 2012. 7. 16 - 2012. 8. 4
//	* Description
//	  ARP packet에 대해 정상 패킷 혹은 비정상 패킷 여부를 판단하는 엔진모듈이다.
//	  지속적으로 패킷을 감청하면서 비정상적인 arp패킷을 판단하고 그 사실을 Message로 알려준다.
//	  일반적으로 정상적인 arp 패킷은 request에 대한 reply만 존재한다.
//	  해당 엔진은 나가는 request패킷의 리스트를 유지하고 들어오는 reply패킷의 적절성 여부를 판단한다.
//	  즉, request되지 않은 reply 패킷은 비정상 패킷으로 간주하고 리스트를 따로 유지한다.
//	  비정상 패킷에 대한 리스트는 크게 SUSPICIUS, ATTACK 두가지가 있다.
//	  해당 IP 주소에 대한 비정상 패킷의 수를 기준으로 SUSPICIUS와 ATTACK 상태가 판단되는데
//	  이 갯수에 대한 정책은 policy.h에 define되어 있다. 
//
///////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////
//
//	'#define's and other preprocessing codes
//
///////////////////////////////////////////////////////////////////////////////////////
#define HAVE_REMOTE
#define MAX_BUF_SIZE 1024
#define snprintf _snprintf

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

///////////////////////////////////////////////////////////////////////////////////////
//
//	'#include's
//
///////////////////////////////////////////////////////////////////////////////////////
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <IPHlpApi.h>
#include "header/op_list.h"
#include "header/spoof_list.h"
#include "header/policy.h"
#include "header/datas.h"
#include "header/get_info.h"
#include "header/log.h"

///////////////////////////////////////////////////////////////////////////////////////
//
//	Prototypes
//
///////////////////////////////////////////////////////////////////////////////////////
void packet_handler_reply(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int get_if_mac(const char *dev_name, u_char *mac_addr);	// 해당 디바이스의 맥주소 가져오는 함수
void arpProc(PARPHDR pARPData, time_t local_tv_sec);
///////////////////////////////////////////////////////////////////////////////////////
//
//	Body
//
///////////////////////////////////////////////////////////////////////////////////////
//=====================================================================================
//
//	* Function : detect_engin
//	* Description 
//		LAN여부를 체크할때 사용하기 위해 자신의 Network ID를 계산하여 저장한다.
//		Winpcap을 사용하여 해당 핸들에서 패킷 포착될 경우 packet_handle_reply를 호출한다.
//
//=====================================================================================
int detect_engin(char *lAdapter)
{
	HEADER_REQUEST = NULL;
	HEADER_REPLY = NULL;
	
	/* 네트워크 정보를 전여역변수에 저장한다 */
	// if_mac: 인터페이스의 맥주소 
	// myIPaddr: 인터페이스의 IPv4 주소
	// netmask : 인터페이스의 넷마스크 주소
	// myNetID : 현재 자신의 네트워크 ID값 (동일 서브넷 여부체크시 사용)
	get_info(lAdapter, if_mac, myIPaddr, netmask);
	myNetID[0] = myIPaddr[0] & netmask[0];
	myNetID[1] = myIPaddr[1] & netmask[1];
	myNetID[2] = myIPaddr[2] & netmask[2];
	myNetID[3] = myIPaddr[3] & netmask[3];

	// Start intercepting data packets.
	pcap_loop(adhandle, 0, packet_handler_reply, NULL);

	return 0;
}

//=====================================================================================
//
//	* Function : detect_engin
//	* Description
//		Callback function invoked by winpcap for every incoming packet 
//		Ether header를 검사하여 arp패킷만 추출하고 해당 패킷은 arpProc에서 처리하도록 한다.
//
//=====================================================================================
void packet_handler_reply(u_char* param, const struct pcap_pkthdr* header,
					const u_char *pkt_data)
{
	time_t local_tv_sec; // 시간
	
	PETHDR lEHdr = (PETHDR) pkt_data;
	local_tv_sec = header->ts.tv_sec; // winpcap 에서 넘겨준 헤더에서 시간 추출

	switch(htons(lEHdr->ether_type)) {
	case 0x0806 : // ARP Packet
		arpProc((PARPHDR)(pkt_data+14), local_tv_sec);
	}
}

//=====================================================================================
//
//	* Function : arpProc
//	* Description 
//		넘어온 arp패킷의 적절성 여부를 판단하는 함수이다. arp패킷 해더와 해당 패킷이 포착된 
//		시간이 인자로 넘어온다. 해당 패킷이 request 패킷이면 request queue에 추가하고
//		reply 패킷이면 request queue에 존재하는지 확인한다. 존재하지 않는다면 비정상 패킷이다.
//		비정상 패킷일 경우 reply queue의 해당 노드를 업데이트 시켜주고 리턴받는 값으로 state를
//		판단한다.
//		그리고 ATTACK, SUSPICIUS LIST의 시간을 해당 비정상 패킷을 수신할 때마다 업데이트 시켜준다.
//		policy.h에 정의된 시간만큼 공격시간이 업데이트 되지 않았을 경우 공격이 멈춘것으로 간주하고
//		리스트에서 삭제하고 정상상태로 변경한다.
//
//=====================================================================================
void arpProc(PARPHDR pARPData, time_t local_tv_sec) {

	int isSusp=0, isAttack=0; // 비정상 패킷일 경우 해당 패킷의 상태를 담을 변수
	char vendor[36];

	/*시간 관련 변수*/
	char timestr[50];		  // 들어온 시간
	char cmptime[50];		  // 비교 시간: 정해진시간(Policy.h에 정의됨)만큼 시간이 update되지 않을 경우 공격이 멈춘것으로 간주한다.
	struct tm *ltime;
	struct tm *lptime;
	struct tm stTempTime;

	//Log 메시지용 변수
	char logmsg[LOG_MSG_SIZE];

	// 패킷 수신 시간 저장
	ltime = localtime(&local_tv_sec);
	memcpy(&stTempTime, ltime, sizeof(struct tm));

	/* 시간 차를 적용하여 저장 */
	local_tv_sec = local_tv_sec - ATTACK_TIME_OVER_SEC;
	lptime = localtime(&local_tv_sec);

	// 정해진 시간 포맷의 문자열 형태로 저장
	strftime( timestr, sizeof(timestr), "%Y-%m-%d %p %I:%M:%S", &stTempTime);
	strftime( cmptime, sizeof(cmptime), "%Y-%m-%d %p %I:%M:%S", lptime);

	// ARP Request Packet from myInterface
	if( ntohs(pARPData->opcode) == ARP_REQUEST 
		&& memcmp(pARPData->spa , myIPaddr, IP_ALEN)==0 ) {

		// request queue에 존재하지 않을 경우 추가
		if( !isRequest(HEADER_REQUEST, pARPData->tpa) ){
			addRequest(HEADER_REQUEST, pARPData->tpa);
		}
	}

	//ARP Reply Packet
	else if( ntohs(pARPData->opcode) == ARP_REPLY 
		&& memcmp(pARPData->spa, myIPaddr, IP_ALEN)!=0 ) { 

		if(!isMyLAN(pARPData->spa)) // 다른 LAN이면 리턴
			return;

		/* Normal Packet Receive */
		if( isRequest(HEADER_REQUEST, pARPData->spa) ) {
			deleteRequest(HEADER_REQUEST, pARPData->spa);	// Delete request from the list

			/* Add as Normal Pakcet */
			search_vendor(oui_list, pARPData->sha, vendor,0,OUI_COUNT-1);

			/* ARP_LIST에 반영 */
			memcpy(ARP_DATA.ipAddr, pARPData->spa, IP_ALEN);
			memcpy(ARP_DATA.macAddr, pARPData->sha, ETH_ALEN);
			strcpy(ARP_DATA.timestr, timestr);
			strcpy(ARP_DATA.vendor, vendor);
			SendMessage(hC1, WM_SPOOF, SM_UPDATE_LIST_NOMAL, (LPARAM)&ARP_DATA);

			/* reply packet delete from the list */
			if( isReplyExist(HEADER_REPLY, pARPData->spa) ) {
				deleteReply(HEADER_REPLY, pARPData->spa);
			}

			/* 정상 패킷에 대해 만일 이전에 의심 혹은 공격상황이었을 경우 리스트에서 삭제한다. */
			if( isSpoof(HEADER_SUSPICIUS, pARPData->spa)) {
				deleteSpoof(HEADER_SUSPICIUS, pARPData->spa, SUSPICIOUS);
			}
			if( isSpoof(HEADER_ATTACK, pARPData->spa)) {
				deleteSpoof(HEADER_ATTACK, pARPData->spa, ATTACK);
			}
		}

		/* Abnormal Packet Receive */
		else { 
			int state; // 상태(정상,의심,공격) 저장
			if(isReplyExist(HEADER_REPLY, pARPData->spa)){ 
				// 이전에도 수신된 비정상적 reply 패킷의 경우 업데이트
				state = updateReply(HEADER_REPLY, pARPData->spa);	
			}
			else {
				// 처음 수신된 경우 의심상태로 결정하고 reply queue에 추가
				state=SUSPICIOUS;
				addReply(HEADER_REPLY, pARPData->sha, pARPData->spa);
			}
			switch(state){ // 상태에 따라 switch
				//Suspicius packet
				case SUSPICIOUS: 
					// vendor 추출
					search_vendor(oui_list, pARPData->sha, vendor,0,OUI_COUNT-1);
					isSusp = isSpoof(HEADER_SUSPICIUS, pARPData->spa);

					// 의심 리스트에 없으면 추가
					// static으로 방어 조치한 경우는 예외로 한다.
					if(!isSusp && !isSpoof(HEADER_STATIC, pARPData->spa) ) { 

						// 추가
						addSpoof(HEADER_SUSPICIUS, SUSPICIOUS, pARPData->spa, pARPData->sha, vendor, timestr, " ");
						
						/* 의심패킷 수신->arplist에 반영 */
						memcpy(ARP_DATA.ipAddr, pARPData->spa, IP_ALEN);
						memcpy(ARP_DATA.macAddr, pARPData->sha, ETH_ALEN);
						strcpy(ARP_DATA.timestr, timestr);
						strcpy(ARP_DATA.vendor, vendor);						
						SendMessage(hC1, WM_SPOOF, SM_UPDATE_LIST_SUSP, (LPARAM)&ARP_DATA);

						// 로그기록
						sprintf(logmsg,"[Warning] Unrequested arp reply packet is detected. TargetIP: %d.%d.%d.%d"
							,pARPData->spa[0],pARPData->spa[1],pARPData->spa[2],pARPData->spa[3], timestr, vendor);
						log(logmsg);
					}
					else if(isSusp){
						 // 기존에 리스트에 존재할 경우 시간 업데이트
						updateSpoof(HEADER_SUSPICIUS, pARPData->spa, timestr);
					}
					break;
				//Attack Packet
				case ATTACK: 
					// vendor 추출
					search_vendor(oui_list, pARPData->sha, vendor,0,OUI_COUNT-1);
					isAttack = isSpoof(HEADER_ATTACK, pARPData->spa);

					// 의심상태 리스트에 있으면 삭제
					if(isSpoof(HEADER_SUSPICIUS, pARPData->spa)){
						deleteSpoof(HEADER_SUSPICIUS, pARPData->spa, SUSPICIOUS);
					}

					// 공격 리스트에 없으면 추가
					// static으로 방어 조치한 경우는 예외로 한다.
					if(!isAttack && !isSpoof(HEADER_STATIC, pARPData->spa)){ 
						addSpoof(HEADER_ATTACK, ATTACK, pARPData->spa, pARPData->sha, vendor, timestr, "");

						/* 공격패킷 수신 -> arplist에 반영*/
						memcpy(ARP_DATA.ipAddr, pARPData->spa, IP_ALEN);
						memcpy(ARP_DATA.macAddr, pARPData->sha, ETH_ALEN);
						strcpy(ARP_DATA.timestr, timestr);
						strcpy(ARP_DATA.vendor, vendor); 
						SendMessage(hC1, WM_SPOOF, SM_UPDATE_LIST_ATTACK, (LPARAM)&ARP_DATA); 

						// 로그기록
						sprintf(logmsg,"[Danger] arp spoofing attack packet is detected. TargetIP: %d.%d.%d.%d"
							,pARPData->spa[0],pARPData->spa[1],pARPData->spa[2],pARPData->spa[3], timestr, vendor);
						log(logmsg);
					}
					else if(isAttack){
						// 기존에 리스트에 존재할 경우 시간 업데이트
						updateSpoof(HEADER_ATTACK, pARPData->spa, timestr);
					}
				};
		}
	}
	// 공격이 멈추었는지 여부를 체크
	refreshSpoofAttack(cmptime);
	refreshSpoofSuspicius(cmptime);
}