///////////////////////////////////////////////////////////////////////////////////////
//
//	* 'ziArp' - a ARP poisoning attack detector
//	* 2012 Summer Handong Global University GHOST U3 Team Open Source Project
//	* File Name		: GUI_Main.cpp
//	* Author		: 김현정,박이삭-(HyunJeong, Isaac)
//	* Date			: 2012. 7. 16 - 2012. 8. 4
//	* Description
//		GUI 메인 윈도우 창을 그려주고, 왼쪽의 신호등 알림창과 알림 메세지를 띄워준다.
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
#include "resource.h"
#include <windows.h>
#include <Windowsx.h>
#include <commctrl.h>
#include <atlstr.h>
#include "header/datas.h"
#include "header/log.h"
#include "header/policy.h"
#include "header/spoof_list.h"
#include "header/get_info.h"

#define MAX_STR 1024
#define WM_SIGNAL WM_USER
#define TRAY_NOTIFY (WM_APP + 100)


///////////////////////////////////////////////////////////////////////////////////////
//
//	Global Variables
//
///////////////////////////////////////////////////////////////////////////////////////
INT STATE = 0;
DWORD ThreadID;
HANDLE hThread;
HINSTANCE g_hInst;
HIMAGELIST hImgSm, hImgLa;
INT devIndex;
MSG Message;
NOTIFYICONDATA nid;
//Log 메시지용 변수
char logmsg[LOG_MSG_SIZE];

///////////////////////////////////////////////////////////////////////////////////////
//
//	Prototypes
//
///////////////////////////////////////////////////////////////////////////////////////
// 윈도우 프로시저
LRESULT CALLBACK WndProc(HWND,UINT,WPARAM,LPARAM);
LRESULT CALLBACK ChildRightProc(HWND,UINT,WPARAM,LPARAM);
LRESULT CALLBACK ChildTopProc(HWND,UINT,WPARAM,LPARAM);
LRESULT CALLBACK ChildBottomProc(HWND,UINT,WPARAM,LPARAM);
//대화상자 
BOOL CALLBACK AboutDlgProc(HWND,UINT,WPARAM,LPARAM);
BOOL CALLBACK InterfaceConfigDlgProc(HWND,UINT,WPARAM,LPARAM);
BOOL CALLBACK LogDlgProc(HWND,UINT,WPARAM,LPARAM);
BOOL CALLBACK HelpDlgProc(HWND,UINT,WPARAM,LPARAM);
BOOL CALLBACK DefenceDlgProc(HWND hDlg,UINT iMessage,WPARAM wParam,LPARAM lParam);
//메시지 처리함수
LRESULT WriteText(HWND,WPARAM,LPARAM);
//기타함수
LRESULT ParseLog(HWND hDlg,UINT iMessage,WPARAM wParam,LPARAM lParam);
void ChangeStatus(HWND,INT);
void SetInterface(INT);
void GetInterface(HWND hWnd,TCHAR* lpString);
void GetAttackList(HWND hWnd,TCHAR* lpString);
void CharToTCHAR(char* char_str, TCHAR* TCHAR_str);
void TCHARToChar(char* char_str, TCHAR* TCHAR_str);
int defence(int index);
extern void ChangeState(void);
extern DWORD WINAPI engin(LPVOID arg);
// 탐색엔진 외부함수
extern void getDevice();

// 윈도우 핸들
HWND hWndMain, hC1, hC3;
extern HWND hC2,  hList;
LPCTSTR lpszClass=TEXT("OpenSource");

///////////////////////////////////////////////////////////////////////////////////////
//
//	Body
//
///////////////////////////////////////////////////////////////////////////////////////

//=====================================================================================
//
//	* Function : 메인 윈도우 및 왼쪽 위,아래 윈도우 생성()
//	* Description 
//		GUI 메인 윈도우 창을 그려주고, 왼쪽의 신호등 알림창과 알림 메세지를 띄워준다.
//
//=====================================================================================
int APIENTRY WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpszCmdParam,int nCmdShow)
{
	HWND hWnd;
	MSG Message;
	WNDCLASS WndClass;
	g_hInst=hInstance;
	
	// 메인 윈도우 클래스
	WndClass.cbClsExtra=0;
	WndClass.cbWndExtra=0;
	WndClass.hbrBackground=NULL;
	WndClass.hCursor=LoadCursor(NULL,IDC_ARROW);
	WndClass.hIcon=LoadIcon(hInstance,MAKEINTRESOURCE(IDI_ICON1));
	WndClass.hInstance=hInstance;
	WndClass.lpfnWndProc=WndProc;
	WndClass.lpszClassName=lpszClass;
	WndClass.lpszMenuName=MAKEINTRESOURCE(IDR_MENU1);
	WndClass.style=CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
	RegisterClass(&WndClass);

	// 오른쪽 차일드 클래스
	WndClass.hbrBackground=(HBRUSH)GetStockObject(WHITE_BRUSH);
	WndClass.lpfnWndProc=ChildRightProc;
	WndClass.lpszClassName=TEXT("ChildRight");
	RegisterClass(&WndClass);

	// 위쪽 차일드 클래스
	WndClass.hbrBackground=(HBRUSH)GetStockObject(WHITE_BRUSH);
	WndClass.lpfnWndProc=ChildTopProc;
	WndClass.lpszClassName=TEXT("ChildTop");
	RegisterClass(&WndClass);

	// 아래쪽 차일드 클래스
	WndClass.hbrBackground=(HBRUSH)GetStockObject(WHITE_BRUSH);
	WndClass.lpfnWndProc=ChildBottomProc;
	WndClass.lpszClassName=TEXT("ChildBottom");
	RegisterClass(&WndClass);
	
	// 메인 윈도우 생성
	hWnd=CreateWindow(lpszClass,lpszClass,WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,CW_USEDEFAULT,1080, 600,
		NULL,(HMENU)NULL,hInstance,NULL);
	ShowWindow(hWnd,nCmdShow);
	hWndMain=hWnd;
	
	while (GetMessage(&Message,NULL,0,0)) {
		TranslateMessage(&Message);
		DispatchMessage(&Message);
	}
	
	return (int)Message.wParam;
}

//=====================================================================================
//
//	* Function : CALLBACK WndProc()
//	* Description 
//		메인 윈도우의 메시지 프로시저
//
//=====================================================================================
LRESULT CALLBACK WndProc(HWND hWnd,UINT iMessage,WPARAM wParam,LPARAM lParam)
{
	RECT crt;
	HDC hdc;
	PAINTSTRUCT ps;
	HMENU hMenu,hPopupMenu;
	POINT pt;

	switch (iMessage) {
	case WM_CREATE:
		hC1=CreateWindow(TEXT("ChildRight"),NULL, WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
			0,0,0,0,hWnd,(HMENU)0,g_hInst,NULL);
		hC2=CreateWindow(TEXT("ChildTop"),NULL, WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_DLGFRAME,
			0,0,0,0,hWnd,(HMENU)0,g_hInst,NULL);
		hC3=CreateWindow(TEXT("ChildBottom"),NULL, WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_DLGFRAME,
			0,0,0,0,hWnd,(HMENU)0,g_hInst,NULL);
		file_firstOpen();
		log("Program Execute");
		getDevice();
		//끌어쓰기
		DialogBox(g_hInst, MAKEINTRESOURCE(IDD_DIALOG_INTERFACE_CONFIG), HWND_DESKTOP, InterfaceConfigDlgProc);
		hThread = CreateThread(NULL,0,engin,(LPVOID)&devIndex,0,&ThreadID);
		SetThreadPriority(hThread, THREAD_PRIORITY_ABOVE_NORMAL);
		return 0;
		 
	case WM_PAINT:
		hdc = BeginPaint(hWnd,&ps);
		EndPaint(hWnd,&ps);
		return 0;

	case WM_COMMAND:
		switch (LOWORD(wParam)){
			//해당 메뉴에서 실행 되어야 할 사항을 입력
		case ID_MENU_LOG:
			DialogBox(g_hInst, MAKEINTRESOURCE(IDD_DIALOG_LOG), HWND_DESKTOP, LogDlgProc);
			break;
		case ID_MENU_EXIT:
			PostQuitMessage(0);
			break;
		case ID_HELP_HELP:
			DialogBox(g_hInst,MAKEINTRESOURCE(IDD_DIALOG_HELP),hWnd,HelpDlgProc);
			break;
		case ID_HELP_INFO:
			DialogBox(g_hInst,MAKEINTRESOURCE(IDD_DIALOG_INFO),hWnd,AboutDlgProc);
			break;
		case IDM_OPEN:
			ShowWindow(hWnd,SW_SHOW);
			nid.cbSize=sizeof(NOTIFYICONDATA);
			nid.hWnd=hWnd;
			nid.uID=0;
			Shell_NotifyIcon(NIM_DELETE, &nid);
			break;
		case IDM_ABOUT:
			DialogBox(g_hInst,MAKEINTRESOURCE(IDD_DIALOG_INFO),hWnd,AboutDlgProc);
			break;
		case IDM_EXIT:
			log("Program Terminate");
			nid.cbSize=sizeof(NOTIFYICONDATA);
			nid.hWnd=hWnd;
			nid.uID=0;
			Shell_NotifyIcon(NIM_DELETE, &nid);
			PostQuitMessage(0);
			return 0;
		}
		return 0;
		//각 윈도우의 크기를 조정해줌
	case WM_SIZE:
		if (wParam != SIZE_MINIMIZED) {
			GetClientRect(hWnd,&crt);
			MoveWindow(hC1,400,0,crt.right-400,crt.bottom,TRUE);
			MoveWindow(hC2,0,0,400,200, TRUE);
			MoveWindow(hC3,0,200,400,crt.bottom-200,TRUE);
		}
		return 0;
		//트레이에서 수행해야 할 작업을 설정해준다.
	case TRAY_NOTIFY:
		switch(lParam){
			//오른쪽 버튼을 누르면 메뉴가 시행되도록 한다.
		case WM_RBUTTONDOWN:
			hMenu=LoadMenu(g_hInst,MAKEINTRESOURCE(IDR_MENU2));
			hPopupMenu=GetSubMenu(hMenu,0);
			GetCursorPos(&pt);
			SetForegroundWindow(hWnd);
			TrackPopupMenu(hPopupMenu,TPM_LEFTALIGN|TPM_LEFTBUTTON|TPM_RIGHTBUTTON,pt.x,pt.y,0,hWnd,NULL);
			SetForegroundWindow(hWnd);
			DestroyMenu(hPopupMenu);
			DestroyMenu(hMenu);
			break;
		}

		return 0;

	case WM_CLOSE:
		//윈도우 창을 닫게 되면 트레이가 생성되도록 한다.
	case WM_DESTROY:
		//트레이 관련함수
		nid.cbSize = sizeof(NOTIFYICONDATA);
		nid.hWnd = hWnd;
		nid.uID = 0;
		nid.uFlags = NIF_ICON|NIF_TIP|NIF_MESSAGE|NIF_INFO;
		nid.uCallbackMessage = TRAY_NOTIFY;
		nid.dwInfoFlags= 0x00004;
		nid.uTimeout = 1000;
		nid.hIcon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_ICON1));
		lstrcpy(nid.szTip, TEXT("zi ARP by GHOST"));
		lstrcpy(nid.szInfoTitle, TEXT("zi ARP 탐지"));
		lstrcpy(nid.szInfo, TEXT("zi ARP 탐지툴이 백그라운드에서 실행되고 있습니다. 완전한 종료를 원하시면 트레이 메뉴에서 종료해주세요."));
		Shell_NotifyIcon(NIM_ADD, &nid);

		ShowWindow(hWnd, SW_HIDE);
		return 0;
	
	}

	return(DefWindowProc(hWnd,iMessage,wParam,lParam));
}

//=====================================================================================
//
//	* Function : CALLBACK ChildTopProc()
//	* Description 
//		위쪽 차일드의 메시지 프로시저
//			상태에 따라 각각 알맞은 신호등의 색깔이 나타나도록 한다.
//
//=====================================================================================
LRESULT CALLBACK ChildTopProc(HWND hWnd,UINT iMessage,WPARAM wParam,LPARAM lParam)
{
	ChangeState();
	
	switch (iMessage) {
	case WM_PAINT:
		switch(STATE){
		case 0:
			ChangeStatus(hWnd, IDB_BIT_GREEN);
			return 0;

		case 1:
			ChangeStatus(hWnd, IDB_BIT_YELLOW);
			return 0;

		case 2:
			ChangeStatus(hWnd, IDB_BIT_RED);
			return 0;
		}

	}
	return(DefWindowProc(hWnd,iMessage,wParam,lParam));
}

//=====================================================================================
//
//	* Function : CALLBACK ChildBottomProc()
//	* Description 
//		아래쪽 차일드의 메시지 프로시저
//			상황에 맞는 메세지를 출력하는 함수를 불러낸다.
//
//=====================================================================================
LRESULT CALLBACK ChildBottomProc(HWND hWnd,UINT iMessage,WPARAM wParam,LPARAM lParam)
{
	switch (iMessage) {

	case WM_PAINT:
		return WriteText(hWnd,wParam,lParam);
	}

	return(DefWindowProc(hWnd,iMessage,wParam,lParam));
}

//=====================================================================================
//
//	* Function : WriteText()
//	* Description 
//		아래쪽 차일드의 메시지 창에 뜰 알림 메세지를 설정해 준다.
//			상태에 따라 맞는 상태 메세지가 뜬다.
//
//=====================================================================================
LRESULT WriteText(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	HDC hdc;
	PAINTSTRUCT ps;
	RECT rt;
	LPTSTR str[]={
		// 정상 상태 문구
		TEXT("\n현재 상태: 안전(Safe)\n\n공격으로 의심되는 패킷이 감지되지 않았습니다."),
		// 경고 상태 문구
		TEXT("\n현재 상태: 경계(Warning)\n\nARP 스푸핑 공격으로 의심되는 패킷이 감지되었습니다.\n\n")
		TEXT(" ▷ 요청하지 않은 응답패킷 감지\n\n")
		TEXT(" ▷ 동일한 패턴의 패킷이 반복될 경우 공격상황으로\n")
		TEXT("     격상됩니다.\n\n")
		TEXT(" ▷ 네트워크를 통해 전달되는 모든 정보는 노출될\n")
		TEXT("     위험이 있습니다.\n"),
		// 공격 상태 문구
		TEXT("\n현재 상태: 위험(Danger)\n\nARP 스푸핑 공격으로 강하게 의심됩니다.\n\n")
		TEXT(" ▷ 요청하지 않은 응답패킷이 지속적으로 감지\n\n")
		TEXT(" ▷ 네트워크를 통해 전달되는 모든 정보는 노출될\n")
		TEXT("     위험이 있습니다.\n\n")
		TEXT(" ▷ 트래픽 감청(스니핑), DNS주소변조(DNS 스푸핑),\n")
		TEXT("     웹페이지변조 공격에 취약할 수 있습니다.\n")
		TEXT("     인터넷 사용에 주의하시기 바랍니다.\n\n")
		TEXT(" ▷ 방어시 정상적인 Mac으로 정적설정됩니다.\n\n")
		TEXT(" ▷ 비정상 패킷이 더이상 발생하지 않으면 정상상태로\n")
		TEXT("     돌아갑니다.")
	};

	GetClientRect(hWnd,&rt);
	hdc=BeginPaint(hWnd,&ps);
	//여기부터 연동시작
	DrawText(hdc,str[STATE],-1,&rt,DT_LEFT|DT_WORDBREAK);
	//여기까지
	EndPaint(hWnd,&ps);

	return 0;
}

//=====================================================================================
//
//	* Function : CALLBACK InterfaceConfigDlgProc()
//	* Description 
//		처음 시작할 때 인터페이스를 설정할 다이알로그를 설정한다. 
//
//=====================================================================================
BOOL CALLBACK InterfaceConfigDlgProc(HWND hDlg, UINT iMessage, WPARAM wParam, LPARAM lParam)
{
	TCHAR lpszStr[MAX_STR];
	HWND hList;
	int itemIndex;
	switch(iMessage){
	case WM_INITDIALOG:
		GetInterface(hDlg,lpszStr);
		return TRUE;
	case WM_COMMAND:
		switch(LOWORD(wParam)){
		case IDOK:
			hList=GetDlgItem(hDlg,IDC_LIST1);
			itemIndex=SendMessage(hList,LB_GETCURSEL,0,0);
			if(SendMessage(hList,LB_GETTEXT,(WPARAM)itemIndex,(LPARAM)lpszStr) == -1)
				return TRUE;
			else{
				SetInterface(itemIndex);
				EndDialog(hDlg,IDOK);
				return TRUE;
			}
		case IDCANCEL:
			EndDialog(hDlg,IDCANCEL);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

//=====================================================================================
//
//	* Function : CALLBACK AboutDlgProc()
//	* Description 
//		상단 메뉴의 about 창에 들어갈 툴에 관한 설명 사항을 쓸 다이알로그를 설정한다.
//
//=====================================================================================
BOOL CALLBACK AboutDlgProc(HWND hDlg, UINT iMessage, WPARAM wParam, LPARAM lParam)
{
	switch(iMessage){
	case WM_INITDIALOG:
		return TRUE;
	case WM_COMMAND:
		switch(LOWORD(wParam)){
		case IDOK:
			EndDialog(hDlg,IDOK);
			return TRUE;
		case IDCANCEL:
			EndDialog(hDlg,IDCANCEL);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

//=====================================================================================
//
//	* Function : CALLBACK LogDlgProc()
//	* Description 
//		상단 메뉴의 log 창에 들어갈 log를 써줄 다이알로그를 설정한다.
//
//=====================================================================================
BOOL CALLBACK LogDlgProc(HWND hDlg, UINT iMessage, WPARAM wParam, LPARAM lParam)
{
	HWND hEdit;
	switch(iMessage){
	case WM_INITDIALOG:
		hEdit=GetDlgItem(hDlg,IDC_EDIT1);
		return ParseLog(hEdit,iMessage,wParam,lParam);
	case WM_COMMAND:
		switch(LOWORD(wParam)){
		case IDOK:
			EndDialog(hDlg,IDOK);
			return TRUE;
		case IDCANCEL:
			EndDialog(hDlg,IDCANCEL);
			return TRUE;
		}
		break;
	}

	return FALSE;
}

//=====================================================================================
//
//	* Function : CALLBACK HelpDlgProc()
//	* Description 
//		상단 메뉴의 help 창에 들어갈 도움말을 써줄 다이알로그를 설정한다.
//
//=====================================================================================
BOOL CALLBACK HelpDlgProc(HWND hDlg, UINT iMessage, WPARAM wParam, LPARAM lParam)
{
	switch(iMessage){
	case WM_INITDIALOG:
		return TRUE;
	case WM_COMMAND:
		switch(LOWORD(wParam)){
		case IDOK:
			EndDialog(hDlg,IDOK);
			return TRUE;
		case IDCANCEL:
			EndDialog(hDlg,IDCANCEL);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

//=====================================================================================
//
//	* Function : CALLBACK DefenceDlgProc()
//	* Description 
//		방어할 ip를 띄워줘 사용자가 해당 아이피를 정적으로 설정하여
//			공격에 대한 방어를 할 수 있도록 하는 부분과 연동되는 프로시저
//
//=====================================================================================
BOOL CALLBACK DefenceDlgProc(HWND hDlg,UINT iMessage,WPARAM wParam,LPARAM lParam)
{
	TCHAR lpszStr[MAX_STR];
	HWND hList;
	int itemIndex;
	switch (iMessage) {
	case WM_INITDIALOG:
		GetAttackList(hDlg,lpszStr);
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDOK:			
			hList=GetDlgItem(hDlg,IDC_LIST1);
			itemIndex=SendMessage(hList,LB_GETCURSEL,0,0);
			if(SendMessage(hList,LB_GETTEXT,(WPARAM)itemIndex,(LPARAM)lpszStr) == -1)
				return TRUE;
			else{
				EndDialog(hDlg,IDOK);
				//방어 엔진으로 연결	
				if(defence(itemIndex)){
					/* static 설정 성공 */
					MessageBox(hDlg, TEXT("정적설정을 완료했습니다."), TEXT("성공"),MB_OK);
				}
				else{
					/* static 설정 실패 */
					MessageBox(hDlg, TEXT("정적설정에 실패했습니다.\n 다시 시도해 주세요."), TEXT("실패"),MB_OK);
				}
				return TRUE;
			}
			return TRUE;
		case IDCANCEL:
			EndDialog(hDlg,IDCANCEL);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

//=====================================================================================
//
//	* Function : ChangeStatus()
//	* Description 
//		위쪽 차일드의 신호등을 상황에 맞게 그려준다.
//
//=====================================================================================
void ChangeStatus(HWND hWnd, INT IDB_BIT )
{
	static TCHAR str[256];
	HDC hdc, hMemDC;
	PAINTSTRUCT ps;
	HBITMAP MyBitmap, OldBitmap;
	BITMAP bit;
	int bx,by;

	hdc=BeginPaint(hWnd,&ps);
	hMemDC=CreateCompatibleDC(hdc);
	MyBitmap=LoadBitmap(g_hInst,MAKEINTRESOURCE(IDB_BIT));
	OldBitmap=(HBITMAP)SelectObject(hMemDC,MyBitmap);

	GetObject(MyBitmap,sizeof(BITMAP),&bit);
	bx=bit.bmWidth;
	by=bit.bmHeight;

	BitBlt(hdc,0,0,bx,by,hMemDC,0,0,SRCCOPY);

	SelectObject(hMemDC,OldBitmap);
	DeleteObject(MyBitmap);
	DeleteDC(hMemDC);
	EndPaint(hWnd,&ps);
}

//=====================================================================================
//
//	* Function : GetInterface()
//	* Description 
//		인터페이스를 가져오는 함수
//
//=====================================================================================
void GetInterface(HWND hWnd,TCHAR* lpString)
{
	TCHAR strDesc[256];
	TCHAR strIP[128];
	int arTab=50;
	PDEVICE_L Link=deviceList;
	while(Link!=NULL){
		wsprintf(strIP,TEXT("%d.%d.%d.%d"),Link->ipAddr[0],Link->ipAddr[1],Link->ipAddr[2],Link->ipAddr[3]);
		CharToTCHAR(Link->desc,strDesc);
		wsprintf(lpString,TEXT("IP주소: %s\t%s"),strIP,strDesc);
		SendDlgItemMessage(hWnd,IDC_LIST1,LB_ADDSTRING,0,(LPARAM)lpString);
		Link=Link->next;
	}
	SendDlgItemMessage(hWnd,IDC_LIST1,LB_SETTABSTOPS,1,(LPARAM)&arTab);
}

//=====================================================================================
//
//	* Function : GetAttackList()
//	* Description 
//		공격리스트를 가져와 방어를 할 때 사용자에게 보여주는 함수
//
//=====================================================================================
void GetAttackList(HWND hWnd,TCHAR* lpString)
{
	TCHAR strMac[18];
	TCHAR strIP[128];
	int arTab=50;
	PSPOOF_L Link=HEADER_ATTACK;
	while(Link!=NULL){
		wsprintf(strIP,TEXT("%d.%d.%d.%d"),
			Link->ipAddr[0],Link->ipAddr[1],Link->ipAddr[2],Link->ipAddr[3]);

		wsprintf(strMac, TEXT("%02X:%02X:%02X:%02X:%02X:%02X"), Link->macAddr[0],Link->macAddr[1],Link->macAddr[2]
		,Link->macAddr[3],Link->macAddr[4],Link->macAddr[5]);
		wsprintf(lpString,TEXT("IP주소: %s\t%s"),strIP,strMac);
		SendDlgItemMessage(hWnd,IDC_LIST1,LB_ADDSTRING,0,(LPARAM)lpString);
		Link=Link->next;
	}
	SendDlgItemMessage(hWnd,IDC_LIST1,LB_SETTABSTOPS,1,(LPARAM)&arTab);
}

//=====================================================================================
//
//	* Function : CharToTCHAR(), TCHARToChar()
//	* Description 
//		char 형과 TCHAR형을 바꿔주는 함수
//
//=====================================================================================
void CharToTCHAR(char* char_str, TCHAR* TCHAR_str)
{
	INT index = 0;
	for(index=0; char_str[index]!=NULL; index++){
		wsprintf(TCHAR_str+index,TEXT("%c"),char_str[index]);
	}
}

void TCHARToChar(char* char_str, TCHAR* TCHAR_str)
{
	INT index = 0;
	
	for(index=0; TCHAR_str[index]!=NULL; index++){
		sprintf(char_str+index,"%c",TCHAR_str[index]);
	}
}

//=====================================================================================
//
//	* Function : SetInterface()
//	* Description 
//		엔진 쓰레드 생성시 넘겨줄 디바이스 인덱스 인자값을 설정하는 함수
//
//=====================================================================================
void SetInterface(INT deviceIndex)
{
	devIndex=deviceIndex;
}

//=====================================================================================
//
//	* Function : ParseLog()
//	* Description 
//		로그 창에 로그 파일에서 읽어온 로그 정보를 띄워주는 함수
//
//=====================================================================================
LRESULT ParseLog(HWND hDlg,UINT iMessage,WPARAM wParam,LPARAM lParam)
{
	HANDLE hLogFile;
	DWORD dwRead;
	char lpBuffer_c[1024]={NULL,};
	static TCHAR* lpBuffer_t=NULL;
	static TCHAR* lpBuffer_tmp[1024]={NULL,};
	INT i = 0; 
	INT index_max=0;
	INT BufSize=0;
	
	hLogFile=CreateFile(filepath,GENERIC_READ,FILE_SHARE_READ,NULL,
	OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	while(1){
		ReadFile(hLogFile,lpBuffer_c,1024,&dwRead,NULL);
		if(dwRead == 0)
			break;
		free(lpBuffer_tmp[i]);
		lpBuffer_tmp[i]=(TCHAR*)malloc((strlen(lpBuffer_c)+1)*sizeof(TCHAR));
		CharToTCHAR(lpBuffer_c,lpBuffer_tmp[i]);
		BufSize+=(strlen(lpBuffer_c)+1)*sizeof(TCHAR);
		
		i++;
	}
	CloseHandle(hLogFile);
	
	index_max=i;
	
	free(lpBuffer_t);
	lpBuffer_t=(TCHAR*)malloc(BufSize);
	wsprintf(lpBuffer_t,TEXT(""));
	for(i=0;i<index_max;i++) {
		wsprintf(lpBuffer_t,TEXT("%s%s"),lpBuffer_t, lpBuffer_tmp[i]);
	}
	SendMessage(hDlg,WM_SETTEXT,0,(LPARAM)lpBuffer_t);
	return TRUE;
}