///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name	: oui.h
//	* Author	: 이승재(Seungjae Lee)
//	* Date		: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		 oui.cpp에 저장되어 있는 OUI Vendor 리스트의 타입을 정의하고 변수를 전역적으로 선언한다.
//
///////////////////////////////////////////////////////////////////////////////////////
#ifndef __OUI_H__
#define __OUI_H__
///////////////////////////////////////////////////////////////////////////////////////
//
//	'#include's
//
///////////////////////////////////////////////////////////////////////////////////////
#include "pkt_header.h"

///////////////////////////////////////////////////////////////////////////////////////
//
//	'#define
//
///////////////////////////////////////////////////////////////////////////////////////
#define OUI_COUNT 16624
#define STR_SIZE  36

///////////////////////////////////////////////////////////////////////////////////////
//
//	'typedef's
//
///////////////////////////////////////////////////////////////////////////////////////
typedef struct OUI_L {
	unsigned char oui[3];
	char vendor[STR_SIZE];
} OUI_L;

///////////////////////////////////////////////////////////////////////////////////////
//
//	Global Variables
//
///////////////////////////////////////////////////////////////////////////////////////
extern OUI_L oui_list[];
#endif