///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name		: arp_scanning.c
//	* Author		: 이승재-(Seungjae Lee)
//					  최서율-(Seoyul Choi)
//	* Date			: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		 log 파일 저장
//
///////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////
//
//	'#include's
//
///////////////////////////////////////////////////////////////////////////////////////

#include <time.h>
#include <string.h>
#include <Windows.h>
#include "header/log.h"
#include "header/policy.h"
#include <signal.h>

///////////////////////////////////////////////////////////////////////////////////////
//
//	Global Variables
//
///////////////////////////////////////////////////////////////////////////////////////

HANDLE hLogFile;
char dir[30];
TCHAR filepath[30];

///////////////////////////////////////////////////////////////////////////////////////
//
//	Prototypes
//
///////////////////////////////////////////////////////////////////////////////////////

void CharToTCHAR(char* char_str, TCHAR* TCHAR_str);

///////////////////////////////////////////////////////////////////////////////////////
//
//	Body
//
///////////////////////////////////////////////////////////////////////////////////////

//=====================================================================================
//
//	* Function : file_firstOpen()
//	* Description 
//		 로그 기록을 저장하기 위한 파일을 생성하는 함수.
//
//=====================================================================================
void file_firstOpen(){
	strcpy(dir,".\\log\\");
	char filename[25];
	char xtns[5] = ".log";
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(filename, 18, "%y%m%d%H%M%S", timeinfo);

	strcat_s(dir, filename);
	strcat_s(dir, xtns);

	CharToTCHAR(dir, filepath);

	CreateDirectory(TEXT("log"), NULL);
	hLogFile = CreateFile(filepath,GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH , NULL);
	
	file_close();
}

//=====================================================================================
//
//	* Function : file_open()
//	* Description 
//		 생성된 파일을 여는 함수.
//
//=====================================================================================
void file_open()
{
	hLogFile = CreateFile(filepath, GENERIC_WRITE, FILE_SHARE_READ, NULL ,OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH , NULL);
}

//=====================================================================================
//
//	* Function : file_close()
//	* Description 
//		 생성된 파일을 닫는 함수.
//
//=====================================================================================
void file_close(){

	CloseHandle(hLogFile);

}

//=====================================================================================
//
//	* Function : log()
//	* Description 
//		 발생한 메시지를 로그 파일에 저장하는 함수.
//
//=====================================================================================
int log(char* message){

	file_open();
	WORD wd = 0xFEFF;
	DWORD nDataSize = 0;
	SetFilePointer(hLogFile, 0 ,NULL, FILE_END);
	char tmp_time[28];
	char newline[]= "\r\n";
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	DWORD dwWritten;
	char msg[LOG_MSG_SIZE];

	strftime(tmp_time, 28, "[%y/%m/%d %p %H:%M:%S] ", timeinfo);
	sprintf(msg, "%s %s", tmp_time, message);
	WriteFile(hLogFile, msg, strlen(msg), &dwWritten, NULL);
	WriteFile(hLogFile, newline, 2, &dwWritten, NULL);
	file_close();
	return 0;

}
