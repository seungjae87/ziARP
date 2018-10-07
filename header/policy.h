///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name	: policy.h
//	* Author	: 이승재(Seunjae Lee)
//	* Date		: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		 정책들을 설정한다.
//
///////////////////////////////////////////////////////////////////////////////////////
#define ATTACK_COUNT_POLICY		2		// 공격 단계를 위한 비정상 패킷 갯수
#define SUSPICIUS_COUNT_POLICY	1		// 의심 단계를 위한 비정상 패킷 갯수
#define ATTACK_TIME_OVER_SEC	35		// 공격이 멈추었음을 판단하는 기준시간 (sec)
#define WAITING_TIME			2000	// ARP Reply waiting time
#define LOG_MSG_SIZE			2048