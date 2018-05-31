#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Shlobj.h>
#include <Shlwapi.h>


WCHAR relpath[MAX_PATH];
WCHAR* getTGPath() {
	WCHAR *buf = new WCHAR[MAX_PATH];
	ZeroMemory(buf, MAX_PATH);
	PWSTR tmp;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &tmp))) {
		wcscat_s(buf, MAX_PATH, tmp);
		wcscat_s(relpath, MAX_PATH, tmp);
		wcscat_s(buf, MAX_PATH, L"\\Telegram Desktop\\Telegram.exe");
		DWORD attribute = GetFileAttributes(buf);
		if (attribute != INVALID_FILE_ATTRIBUTES && !(attribute & FILE_ATTRIBUTE_DIRECTORY)) {
			return buf;
		}
		else {
			return nullptr;
		}
	}
	return nullptr;
}
int main()
{
	STARTUPINFO si = { 0, };
	PROCESS_INFORMATION pi;
	ZeroMemory(relpath, MAX_PATH);
	WCHAR *path;
	path = getTGPath();
	if (path == nullptr) {
		printf("Cannot find telegram executable file.\n");
		exit(-1);
	}
	printf("Path: %S\n", path);
	BOOL state;
	state = CreateProcess(NULL, path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, relpath, &si,&pi);
	if (state == NULL) {
		printf("Cannot create process.\n");
		exit(-1);
	}
	LPVOID addr = (LPVOID)0x019eb23c;
	char tmp[6];
	ZeroMemory(tmp, sizeof(tmp));
	char newtext[] = "Noto Sans CJK KR Regular\x00";
	DWORD written = 0;
	ReadProcessMemory(pi.hProcess, addr, tmp, 5, NULL);
	printf("%s\n", tmp);
	if (!strcmp(tmp, "Gulim")) {
		BOOL ret;
		printf("Previous font found as Gulim. Patching..\n");
		DWORD old;
		//MapViewOfFile()
		ret = VirtualProtectEx(pi.hProcess,addr, sizeof(newtext), PAGE_EXECUTE_READWRITE, &old);
		if (ret == 0) {
			printf("Last error: %d\n", GetLastError());
		}
		ret = WriteProcessMemory(pi.hProcess, addr, newtext, sizeof(newtext), &written);
		printf("Ret: %d\n", ret);
		if (ret == 0) {
			printf("Last error: %d\n", GetLastError());
		}
		ret = VirtualProtectEx(pi.hProcess, addr, sizeof(newtext), old, NULL);
		printf("Ret: %d\n", ret);
		if (ret == 0) {
			printf("Last error: %d\n", GetLastError());
		}
	}
	else {
		printf("Gulim font is not found.\n");
	}
	ResumeThread(pi.hThread);
	delete path;
	exit(0);
    return 0;
}

