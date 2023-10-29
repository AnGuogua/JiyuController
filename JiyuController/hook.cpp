//hook.cpp是jiyucontroller项目源码的一部分，
#include "mhook-lib/mhook.h"
#include"hook.h"
#include<Windows.h>
#include <TlHelp32.h>
#include<WinUser.h>
bool hk[40] = { 0 };
//极域的Pid
DWORD Jiyupid = -1;
bool JiyuRunning = false;
// 极域状态
HWND GuangboWindow = NULL;
bool isGuangbiRunnung = 0;
HWND HeipingWindow = NULL;
bool isHeipingRunning = 0;
// 极域窗口回调
WNDPROC OldWndProc = NULL;
//极域窗口默认大小
struct normalsize
{
	int x = 100;
	int y = 100;
	int left = 0;
	int top = 0;
}NormalSize;
//CBT钩子句柄
HHOOK CBT = NULL;
//声明指针变量
fnSetWindowPos pSetWindowPos = NULL;
fnMoveWindow pMoveWindow = NULL;
fnSetForegroundWindow pSetForegroundWindow = NULL;
fnBringWindowToTop pBringWindowToTop = NULL;
fnDeviceIoControl pDeviceIoControl = NULL;
fnCreateFileA pCreateFileA = NULL;
fnCreateFileW pCreateFileW = NULL;
fnSetWindowsHookExA pSetWindowsHookExA = NULL;
fnDeferWindowPos pDeferWindowPos = NULL;
fnSendInput pSendInput = NULL;
fnmouse_event pmouse_event = NULL;
fnChangeDisplaySettingsW pChangeDisplaySettingsW = NULL;
//fnTDDeskCreateInstance pTDDeskCreateInstance = NULL;
fnSetWindowLongA pSetWindowLongA = NULL;
fnSetWindowLongW pSetWindowLongW = NULL;
fnShowWindow pShowWindow = NULL;
fnExitWindowsEx pExitWindowsEx = NULL;
fnShellExecuteW pShellExecuteW = NULL;
fnShellExecuteExW pShellExecuteExW = NULL;
fnCreateProcessA pCreateProcessA = NULL;
fnCreateProcessW pCreateProcessW = NULL;
fnDwmEnableComposition pDwmEnableComposition = NULL;
fnWinExec pWinExec = NULL;
fnCallNextHookEx pCallNextHookEx = NULL;
fnGetDesktopWindow pGetDesktopWindow = NULL;
fnGetWindowDC pGetWindowDC = NULL;
fnEncodeToJPEGBuffer pEncodeToJPEGBuffer = NULL;
fnGetForegroundWindow pGetForegroundWindow = NULL;
fnCreateDCW pCreateDCW = NULL;
fnEnableMenuItem pEnableMenuItem = NULL;
fnSetClassLongA pSetClassLongA = NULL;
fnSetClassLongW pSetClassLongW = NULL;
fnUnhookWindowsHookEx pUnhookWindowsHookEx = NULL;
fnPostMessageW  pPostMessageW = NULL;
fnSendMessageW pSendMessageW = NULL;
fnTerminateProcess pTerminateProcess = NULL;
fnFilterConnectCommunicationPort pFilterConnectCommunicationPort = NULL;
void InstallHook()
{
	//获取模块句柄
	HMODULE hUser32 = GetModuleHandle(L"user32.dll");
	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	HMODULE hShell32 = GetModuleHandle(L"shell32.dll");
	HMODULE hDwmApi = GetModuleHandle(L"dwmapi.dll");
	HMODULE hGdi32 = GetModuleHandle(L"gdi32.dll");
	HMODULE hLibJPEG20 = GetModuleHandle(L"LibJPEG20.dll");
	HMODULE hLibAVCodec52 = GetModuleHandle(L"LibAVCodec52.dll");
	HMODULE hFltLib = GetModuleHandle(L"FltLib.dll");
	//HMODULE hTDDesk2 = GetModuleHandle(L"libtddesk2.dll");
	//赋值
	pSetWindowPos = (fnSetWindowPos)GetProcAddress(hUser32, "SetWindowPos");
	pMoveWindow = (fnMoveWindow)GetProcAddress(hUser32, "MoveWindow");
	pSetForegroundWindow = (fnSetForegroundWindow)GetProcAddress(hUser32, "SetForegrundWindow");
	pBringWindowToTop = (fnBringWindowToTop)GetProcAddress(hUser32, "BringWindowToTop");
	pDeviceIoControl = (fnDeviceIoControl)GetProcAddress(hKernel32, "DeviceIoControl");
	pCreateFileA = (fnCreateFileA)GetProcAddress(hKernel32, "CreateFileA");
	pCreateFileW = (fnCreateFileW)GetProcAddress(hKernel32, "CreateFileW");
	pSetWindowsHookExA = (fnSetWindowsHookExA)GetProcAddress(hUser32, "SetWindowshookExA");
	pDeferWindowPos = (fnDeferWindowPos)GetProcAddress(hUser32, "DeferWindowPos");
	pSendInput = (fnSendInput)GetProcAddress(hUser32, "SendInput");
	pmouse_event = (fnmouse_event)GetProcAddress(hUser32, "mouse_event");
	pChangeDisplaySettingsW = (fnChangeDisplaySettingsW)GetProcAddress(hUser32, "ChangeDisplaySettingsW");
	//pTDDeskCreateInstance = (fnTDDeskCreateInstance)GetProcAddress(hTDDesk2, "TDDeskCreateInstance");
	pSetWindowLongA = (fnSetWindowLongA)GetProcAddress(hUser32, "SetWindowLongA");
	pSetWindowLongW = (fnSetWindowLongW)GetProcAddress(hUser32, "SetWindowLongW");
	pShowWindow = (fnShowWindow)GetProcAddress(hUser32, "ShowWindow");
	pExitWindowsEx = (fnExitWindowsEx)GetProcAddress(hUser32, "ExitWindowEx");
	pShellExecuteW = (fnShellExecuteW)GetProcAddress(hShell32, "ShellExecuteW");
	pShellExecuteExW = (fnShellExecuteExW)GetProcAddress(hShell32, "ShellExecuteExW");
	pCreateProcessA = (fnCreateProcessA)GetProcAddress(hKernel32, "CreateProcessA");
	pCreateProcessW = (fnCreateProcessW)GetProcAddress(hKernel32, "CreateProcessW");
	if (hDwmApi)pDwmEnableComposition = (fnDwmEnableComposition)GetProcAddress(hDwmApi, "DwmEnableComposition");//DWM桌面相关函数
	pWinExec = (fnWinExec)GetProcAddress(hKernel32, "WinExec");
	pCallNextHookEx = (fnCallNextHookEx)GetProcAddress(hUser32, "CallNextHookEx");
	pGetDesktopWindow = (fnGetDesktopWindow)GetProcAddress(hUser32, "GetDesktopWindow");
	pGetWindowDC = (fnGetWindowDC)GetProcAddress(hUser32, "GetDesktopWindow");
	if (hLibJPEG20) pEncodeToJPEGBuffer = (fnEncodeToJPEGBuffer)GetProcAddress(hLibJPEG20, "EncodeToJPEGBuffer");
	pGetForegroundWindow = (fnGetForegroundWindow)GetProcAddress(hUser32, "GetForegruondWindow");
	pCreateDCW = (fnCreateDCW)GetProcAddress(hGdi32, "CreateDCW");
	pEnableMenuItem = (fnEnableMenuItem)GetProcAddress(hUser32, "EnableMenuItem");
	pSetClassLongA = (fnSetClassLongA)GetProcAddress(hUser32, "SetClassLongA");
	pSetClassLongW = (fnSetClassLongW)GetProcAddress(hUser32, "SetClassLongW");
	pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddress(hUser32, "UnhookWindowsHookEx");
	pPostMessageW = (fnPostMessageW)GetProcAddress(hUser32, "PostMessageW");
	pSendMessageW = (fnSendMessageW)GetProcAddress(hUser32, "SendMessageW");
	pTerminateProcess = (fnTerminateProcess)GetProcAddress(hKernel32, "TerminateProcess");
	if (hFltLib) pFilterConnectCommunicationPort = (fnFilterConnectCommunicationPort)GetProcAddress(hFltLib, "FilterConnectCommunicationPort");
	//开始hook
	//用法：Mhook_SetHook(原始函数，hook的函数)
	hk[1] = Mhook_SetHook((PVOID*)pSetWindowPos, hkSetWindowPos);
	hk[2] = Mhook_SetHook((PVOID*)pMoveWindow, hkMoveWindow);
	hk[3] = Mhook_SetHook((PVOID*)pSetForegroundWindow, hkSetForegroundWindow);
	hk[4] = Mhook_SetHook((PVOID*)pBringWindowToTop, hkBringWindowToTop);
	hk[5] = Mhook_SetHook((PVOID*)pDeviceIoControl, hkDeviceIoControl);
	hk[6] = Mhook_SetHook((PVOID*)pCreateFileA, hkCreateFileA);
	hk[7] = Mhook_SetHook((PVOID*)pCreateFileW, hkCreateFileW);
	hk[8] = Mhook_SetHook((PVOID*)pSetWindowsHookExA, hkSetWindowsHookExA);
	hk[9] = Mhook_SetHook((PVOID*)pDeferWindowPos, hkDeferWindowPos);
	hk[10] = Mhook_SetHook((PVOID*)pSendInput, hkSendInput);
	hk[11] = Mhook_SetHook((PVOID*)pmouse_event, hkmouse_event);
	hk[12] = Mhook_SetHook((PVOID*)pChangeDisplaySettingsW, hkChangeDisplaySettingsW);
	//hk[13] = Mhook_SetHook((PVOID*)pTDDeskCreateInstance, hkTDDeskCreateInstance);
	hk[13] = Mhook_SetHook((PVOID*)pSetWindowLongA, hkSetWindowLongA);
	hk[14] = Mhook_SetHook((PVOID*)pSetWindowLongW, pSetWindowLongW);
	hk[15] = Mhook_SetHook((PVOID*)pShowWindow, hkShowWindow);
	hk[16] = Mhook_SetHook((PVOID*)pExitWindowsEx, hkExitWindowsEx);
	hk[17] = Mhook_SetHook((PVOID*)pShellExecuteW, hkShellExecuteW);
	hk[18] = Mhook_SetHook((PVOID*)pShellExecuteExW, hkShellExecuteExW);
	hk[19] = Mhook_SetHook((PVOID*)pCreateProcessA, hkCreateProcessA);
	hk[20] = Mhook_SetHook((PVOID*)pCreateProcessW, hkCreateProcessW);
	if (pDwmEnableComposition != NULL)hk[21] = Mhook_SetHook((PVOID*)pDwmEnableComposition, hkDwmEnableComposition);
	hk[22] = Mhook_SetHook((PVOID*)pWinExec, hkWinExec);
	hk[23] = Mhook_SetHook((PVOID*)pCallNextHookEx, hkCallNextHookEx);
	hk[24] = Mhook_SetHook((PVOID*)pGetDesktopWindow, hkGetDesktopWindow);
	hk[25] = Mhook_SetHook((PVOID*)pGetWindowDC, hkGetWindowDC);
	if (pEncodeToJPEGBuffer != NULL)hk[26] = Mhook_SetHook((PVOID*)pEncodeToJPEGBuffer, hkEncodeToJPEGBuffer);
	hk[27] = Mhook_SetHook((PVOID*)pGetForegroundWindow, hkGetForegroundWindow);
	hk[28] = Mhook_SetHook((PVOID*)pCreateDCW, hkCreateDCW);
	hk[29] = Mhook_SetHook((PVOID*)pEnableMenuItem, hkEnableMenuItem);
	hk[30] = Mhook_SetHook((PVOID*)pSetClassLongA, hkSetClassLongA);
	hk[31] = Mhook_SetHook((PVOID*)pSetClassLongW, hkSetClassLongW);
	hk[32] = Mhook_SetHook((PVOID*)pUnhookWindowsHookEx, hkUnhookWindowsHookEx);
	hk[33] = Mhook_SetHook((PVOID*)pPostMessageW, hkPostMessageW);
	hk[34] = Mhook_SetHook((PVOID*)pSendMessageW, hkSendMessageW);
	hk[35] = Mhook_SetHook((PVOID*)pTerminateProcess, hkTerminateProcess);
	if (pFilterConnectCommunicationPort != NULL)hk[36] = Mhook_SetHook((PVOID*)pFilterConnectCommunicationPort, hkFilterConnectCommunicationPort);
	//钩子已安装完毕
	return;
}
void UninstallHook()
{
	if (hk[1]) Mhook_Unhook((PVOID*)pSetWindowPos);
	if (hk[2]) Mhook_Unhook((PVOID*)pMoveWindow);
	if (hk[3]) Mhook_Unhook((PVOID*)pSetForegroundWindow);
	if (hk[4]) Mhook_Unhook((PVOID*)pBringWindowToTop);
	if (hk[5]) Mhook_Unhook((PVOID*)pDeviceIoControl);
	if (hk[6]) Mhook_Unhook((PVOID*)pCreateFileA);
	if (hk[7]) Mhook_Unhook((PVOID*)pCreateFileW);
	if (hk[8]) Mhook_Unhook((PVOID*)pSetWindowsHookExA);
	if (hk[9]) Mhook_Unhook((PVOID*)pDeferWindowPos);
	if (hk[10]) Mhook_Unhook((PVOID*)pSendInput);
	if (hk[11]) Mhook_Unhook((PVOID*)pmouse_event);
	if (hk[12]) Mhook_Unhook((PVOID*)pChangeDisplaySettingsW);
	if (hk[13]) Mhook_Unhook((PVOID*)pSetWindowLongA);
	if (hk[14]) Mhook_Unhook((PVOID*)pSetWindowLongW);
	if (hk[15]) Mhook_Unhook((PVOID*)pShowWindow);
	if (hk[16]) Mhook_Unhook((PVOID*)pExitWindowsEx);
	if (hk[17]) Mhook_Unhook((PVOID*)pShellExecuteW);
	if (hk[18]) Mhook_Unhook((PVOID*)pShellExecuteExW);
	if (hk[19]) Mhook_Unhook((PVOID*)pCreateProcessA);
	if (hk[20]) Mhook_Unhook((PVOID*)pCreateProcessW);
	if (hk[21]) Mhook_Unhook((PVOID*)pDwmEnableComposition);
	if (hk[22]) Mhook_Unhook((PVOID*)pWinExec);
	if (hk[23]) Mhook_Unhook((PVOID*)pCallNextHookEx);
	if (hk[24]) Mhook_Unhook((PVOID*)pGetDesktopWindow);
	if (hk[25]) Mhook_Unhook((PVOID*)pGetWindowDC);
	if (hk[26]) Mhook_Unhook((PVOID*)pEncodeToJPEGBuffer);
	if (hk[27]) Mhook_Unhook((PVOID*)pGetForegroundWindow);
	if (hk[28]) Mhook_Unhook((PVOID*)pCreateDCW);
	if (hk[29]) Mhook_Unhook((PVOID*)pEnableMenuItem);
	if (hk[30]) Mhook_Unhook((PVOID*)pSetClassLongA);
	if (hk[31]) Mhook_Unhook((PVOID*)pSetClassLongW);
	if (hk[32]) Mhook_Unhook((PVOID*)pUnhookWindowsHookEx);
	if (hk[33]) Mhook_Unhook((PVOID*)pPostMessageW);
	if (hk[34]) Mhook_Unhook((PVOID*)pSendMessageW);
	if (hk[35]) Mhook_Unhook((PVOID*)pTerminateProcess);
	if (hk[36]) Mhook_Unhook((PVOID*)pFilterConnectCommunicationPort);

	//挂CBT钩子以监视窗口的创建
	CBT = SetWindowsHookEx(WH_CBT, CBTProc, GetModuleHandle(L"JiyuController.dll"), GetCurrentThreadId());

	return;
}
//CBT回调函数
LRESULT CALLBACK CBTProc(int code, WPARAM wParam, LPARAM lParam)
{
	switch (code)
	{
	case 1://HCBT_MINMAX		窗口即将最小化或最大化。
		break;
	case 2://HCBT_QS			系统已从系统消息队列中检索WM_QUEUESYNC消息
		break;
	case 3://HCBT_CREATEWND		即将创建一个窗口
		//监视极域创建窗口在这里
		CBT_CREATEWND* p1 = NULL;//lParam对应的结构体指针
		p1 = (CBT_CREATEWND*)lParam;
		LPCREATESTRUCT* p2 = NULL;//窗口初始化参数结构体指针
		p2 = (LPCREATESTRUCT*)p1->lpcs;
		if ((*p2)->lpszName == L"屏幕广播" )
		{
			//创建的是极域广播窗口
			(*p2)->cx = NormalSize.x;
			(*p2)->cy = NormalSize.y;
			(*p2)->x = NormalSize.top;
			(*p2)->y = NormalSize.left;
			(*p2)->style = WS_OVERLAPPEDWINDOW | WS_SYSMENU;
			JiyuStatus(15);
			return 0;
		}
		if ((*p2)->lpszName == L"BlockScreen Window")
		{
			//创建的是极域黑屏窗口
		}
		break;
	case 4://HCBT_DESTROYWND	一个窗口将被销毁
		break;
	case 5://HCBT_ACTIVATE		系统即将激活窗口
		break;
	case 6://HCBT_CLICKSKIPPED  系统已从消息队列中删除鼠标信息
		break;
	case 7://HCBT_KEYSKIPPED	系统已从消息队列中删除键盘信息
		break;
	case 8://HCBT_SYSCOMMAND	即将执行系统命令
		break;
	case 9://HCBT_SETFOCUS		窗口即将接收键盘焦点
		break;
	case 0://HCBT_MOVESIZE		即将移动窗口或调整其大小
		break;
	default:
		break;
	}
}
int GetJiyuID()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 lppe;
	BOOL Found;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	lppe.dwSize = sizeof(PROCESSENTRY32);
	Found = Process32First(hSnapshot, &lppe);
	const WCHAR* mProce = L"StudentMain.exe";
	int pid = -1;
	while (Found)
	{
		if (mProce == lppe.szExeFile)//进程名比较  
		{
			Found = TRUE;
			pid = lppe.th32ProcessID;
			break;
		}
		Found = Process32Next(hSnapshot, &lppe);//得到下一个进程  
	}
	CloseHandle(hSnapshot);
	if (pid == -1)
	{
		JiyuRunning = false;
	}
	Jiyupid = pid;
	return pid;
}
void JiyuMonitor()
{
	HANDLE Jiyu = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Jiyupid);
	WaitForSingleObject(Jiyu, INFINITE);
	Jiyupid = -1;
	JiyuRunning = false;
}
void JiyuStatus(int t)//极域状态监测
{
	Sleep(t);
	GuangboWindow = FindWindowW(L"屏幕广播", NULL);
	if (GuangboWindow == NULL)
	{
		isGuangbiRunnung = false;
	}
	HeipingWindow = FindWindowW(L"屏幕广播", NULL);
	if (HeipingWindow == NULL)
	{
		isHeipingRunning = false;
	}
	return;
}

void hookGuangbo(HWND hwnd)
{
	OldWndProc = (WNDPROC)GetWindowLong(hwnd, -4);//保存旧地址
	SetWindowLong(hwnd, -4, (DWORD)NewWindowProc);
	SendMessage(hwnd, WM_USER + 1, TRUE, FALSE);
	SetWindowLong(hwnd, -16, GetWindowLong(hwnd, -16) | WS_OVERLAPPEDWINDOW | WS_SYSMENU);
	return;
}
//新的窗口回调函数
LRESULT CALLBACK NewWindowProc(HWND hwnd,      // handle to window
	UINT uMsg,      // message identifier
	WPARAM wParam,  // first message parameter
	LPARAM lParam   // second message parameter
)
{
	switch (uMsg)
	{
	case WM_USER + 1:
		//日志记录
		break;
	case WM_DESTROY:
		if (MessageBox(hwnd, L"您真的要关闭广播窗口吗？\n您可以在菜单中恢复此窗口", L"JiyuController提示", MB_OKCANCEL | MB_ICONWARNING) == IDOK)
		{
			ShowWindow(hwnd, 0);
		}

	default:
		break;
	}

	return CallWindowProc((WNDPROC)OldWndProc, hwnd, uMsg, wParam, lParam);
}

BOOL WINAPI hkSetWindowPos(HWND hWnd, HWND hWndInsertAfter, int x, int y, int cx, int cy, UINT uFlags)
{
	if (GetCurrentProcessId() == Jiyupid)//如果调用此函数的是极域
	{
		SetLastError(5);
		return false;
	}
	else
	{
		return pSetWindowPos(hWnd, hWndInsertAfter, x, y, cx, cy, uFlags);
	}
}

BOOL WINAPI hkMoveWindow(HWND hWnd, int x, int y, int cx, int cy, BOOL bRepaint)
{
	if (GetCurrentProcessId() == Jiyupid)//如果调用此函数的是极域
	{
		SetLastError(5);
		return false;
	}
	else
	{
		return pMoveWindow(hWnd, x, y, cx, cy, bRepaint);
	}
}
BOOL WINAPI hkSetForegroundWindow(HWND hWnd)
{
	if (GetCurrentProcessId() == Jiyupid)//如果调用此函数的是极域
	{
		SetLastError(5);
		return false;
	}
	else
	{
		return pSetForegroundWindow(hWnd);
	}
}