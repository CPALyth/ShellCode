// InjectShellCode.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <windows.h>
#include <iostream>

using namespace std;

// 定义要用到的函数指针
// GetProcAddress
typedef FARPROC (WINAPI *PGETPROCADDRESS)(HMODULE hModule, LPCTSTR lpProcName);	
// LoadLibrary
typedef HMODULE (WINAPI *PLOADLIBRARY)(LPCSTR lpFileName);	
// MessageBox,此处填写你要用到的API的函数指针
typedef int (WINAPI *PMESSAGEBOX)(HWND hWnd, LPCTSTR lpText, LPCSTR lpCaption, UINT uType);	

struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
};

struct PEB_LDR_DATA 
{
	DWORD Length;
	BYTE Initialized;
	VOID* SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	VOID* EntryInProgress;
};

struct LDR_DATA_TABLE_ENTRY 
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	VOID* DllBase;
	VOID* EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;
	LIST_ENTRY HashLinks;
	VOID* SectionPointers;
	DWORD CheckSum;
	DWORD TimeDateStamp;
	VOID* LoadedImports;
	VOID* EntryPointActivationContext;
	VOID* PatchInformation;
};

void ShellCode()
{
	LDR_DATA_TABLE_ENTRY* pPLD = NULL, *pBeg = NULL;
	PGETPROCADDRESS pGetProcAddress = NULL;
	PMESSAGEBOX pMessageBox = NULL;
	PLOADLIBRARY pLoadLibrary = NULL;
	WORD *pFirst = NULL, *pLast = NULL;
	DWORD ret = 0, i = 0;
	DWORD dwKernelBase = 0;

	char szKernel32[] = { 'K',0,'E',0,'R',0,'N',0,'E',0,'L',0,'3',0,'2',0,'.',0,'D',0,'L',0,'L',0 ,0,0 };	// 注意这里,有时候是小写的,有时候是首字母大写的
	char szUser32[] = { 'U','S','E','R','3','2','.','d','l','l',0 };	// 此处填写你要用到的API是哪个dll导出的

	char szGetProcAddr[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };
	char szLoadLibraty[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	char szMessageBox[] = { 'M','e','s','s','a','g','e','B','o','x','A',0 };	// 此处填写你要用到的API

	// 获取链表 TEB->PEB->PEB_LDR_DATA->LDR_DATA_TABLE_ENTRY
	__asm
	{
		mov eax,fs:[0x30]	// PEB
		mov eax,[eax+0x0C]	// PEB_LDR_DATA
		add eax,0xC		
		mov pBeg,eax	// pBeg = InLoadOrderModuleList
		mov eax,[eax]
		mov pPLD,eax	// pPLD = InLoadOrderModuleList.Flink
	}
	// 遍历找到Kernel32.dll的基址
	while (pPLD != pBeg)
	{
		// 这里由于不能使用API,而两个字符串都是UNICODE型,所以逐双字节比较
		pLast = (WORD *)pPLD->BaseDllName.Buffer;	// 取两个字节,双向链表第一个元素的dll名称
		pFirst = (WORD *)szKernel32;				// 取两个字节,即'k',0
		while (*pFirst && *pFirst == *pLast)
		{
			pFirst++;
			pLast++;
		}
		if (*pFirst == *pLast)
		{
			dwKernelBase = (DWORD)pPLD->DllBase;
			break;
		}
		pPLD = (LDR_DATA_TABLE_ENTRY*)pPLD->InLoadOrderLinks.Flink;
	}

	// 遍历Kernel32.dll的导出表,找到GetProcAddress函数的地址
	IMAGE_DOS_HEADER* pIDH = (IMAGE_DOS_HEADER*)dwKernelBase;
	IMAGE_NT_HEADERS* pINH = (IMAGE_NT_HEADERS*)(dwKernelBase + pIDH->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* pIED = (IMAGE_EXPORT_DIRECTORY*)(dwKernelBase +
		pINH->OptionalHeader.DataDirectory[0].VirtualAddress);

	DWORD* pAddrOfFunc = (DWORD*)(dwKernelBase + pIED->AddressOfFunctions);	// 导出函数地址表RVA
	DWORD* pAddrOfName = (DWORD*)(dwKernelBase + pIED->AddressOfNames);		// 导出函数名称表RVA
	WORD* pAddrOfOrd = (WORD*)(dwKernelBase + pIED->AddressOfNameOrdinals);	// 导出函数序号表RVA
	DWORD dwCnt = 0;

	char* pFinded = NULL;
	char* pSrc = szGetProcAddr;
	for(; dwCnt < pIED->NumberOfNames; ++dwCnt)
	{
		pFinded = (char*)(dwKernelBase + pAddrOfName[dwCnt]);
		while (*pFinded && *pFinded == *pSrc )
		{
			pFinded++;
			pSrc++;
		}
		if (*pFinded == *pSrc)
		{
			pGetProcAddress = (PGETPROCADDRESS)(dwKernelBase + pAddrOfFunc[pAddrOfOrd[dwCnt]]);
			break;
		}
		pSrc = szGetProcAddr;
	}
	pLoadLibrary = (PLOADLIBRARY)pGetProcAddress((HMODULE)dwKernelBase, (LPCTSTR)szLoadLibraty);
	//在此添加你要使用的 模块基址 和 API名
	pMessageBox = (PMESSAGEBOX)pGetProcAddress(pLoadLibrary(szUser32), (LPCTSTR)szMessageBox);
	// 调用函数
	char szTitle[] = { 'T','i','t','l','e',0 };
	char szContent[] = { 'C','o','t','e','n','t',0 };
	pMessageBox(NULL, (LPCTSTR)szContent, szTitle, 0);
}



int main()
{
	ShellCode();
}
