#include <stdio.h>
#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <conio.h>
#include "communication.h"
#include "fuzz.h"
#include "mutate.h"
#include <Shlwapi.h>
#include <tlhelp32.h>

//#define IN_VM

// 實驗結果輸出位置
#ifdef IN_VM
#define LOG_PATH "C:\\Users\\user\\Desktop\\Find_Anti\\output\\ph1_"
#define LOG_PATH2 "C:\\Users\\user\\Desktop\\Find_Anti\\output\\ph2_"
#define LOG_PATH3 "C:\\Users\\user\\Desktop\\Find_Anti\\output\\ph3_"
#define DONE_PATH "C:\\Users\\user\\Desktop\\Find_Anti\\output\\done.txt"
//#define TARGET_DLL "C:\\Users\\user\\Desktop\\Find_Anti\\mut_DLL.dll"
#else
//#define LOG_PATH "C:\\Program_Code\\Find_Anti\\Final_Mut\\output\\ph1_"
//#define LOG_PATH2 "C:\\Program_Code\\Find_Anti\\Final_Mut\\output\\ph2_"
//#define LOG_PATH3 "C:\\Program_Code\\Find_Anti\\Final_Mut\\output\\ph3_"
//#define DONE_PATH "C:\\Program_Code\\Find_Anti\\Final_Mut\\output\\done.txt"
//#define TARGET_DLL "C:\\Program_Code\\Find_Anti\\Final_Mut\\Debug\\mut_DLL.dll"
#define LOG_PATH "output\\ph1_"
#define LOG_PATH2 "output\\ph2_"
#define LOG_PATH3 "output\\ph3_"
#define DONE_PATH "output\\done.txt"
#endif // 

#define TARGET_DLL "mut_DLL.dll"

using namespace std;



///////// IMPORTANT NOTE: Make sure to enable 32BIT_SYS when running on NUC for GetTickCount hooks!

#define __DEBUG_PRINT
//#define __EXPERIMENT_PHASE1
#define __EVALUATION


// VM
//#define TARGET_DLL "C:\\Users\\Lisa\\Documents\\ph1\\EnviralDLL.dll"
//#define TARGET_DLL "C:\\Program_Code\\Find_Anti\\WTF\\Debug\\WTF_DLL.dll"


#define BACKTRACK_TIME_LIMIT 500000 // 500 sec (~8.3 min)
#define MUTATE_TIME_LIMIT 50000 // 50 sec (50 x 1000)
#define LAUNCH_TIME_LIMIT 2500 // 2.5s


#define GAIN_THRESHOLD 1

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Winmm.lib")

Frame* frameCurr = NULL;
Frame* frameBest = NULL;

HANDLE SyncEvent = NULL;
HANDLE hThreads[MAX_CHILD];
DWORD dwThreadCount = 0;

DWORD pids[MAX_PIDS];
DWORD pidptr = 0;

//  回溯用Mutation變數
Mutation* mutBackTrack = NULL;

BOOL IsPrintable(wchar_t* str) {
	size_t len = wcslen(str);
	for (size_t i = 0; i < len; i++) {
		if (!iswprint(str[i]) || str[i] >= 191) {
			return FALSE;
		}
	}
	return TRUE;
}

// 將Recording加入到當前exec的本地呼叫紀錄中，用index來區分不同線程
int AddRecordToList(Execution* exec, Recording* rec, LONG index)
{
	/* The head is the most recent (temporal last) call */
	// recordings這個list是反向增長的，最後一個呼叫是頭部

	// 若這個List是空的，則創建一個新的空間給他
	if (exec->recordings[index].recHead == NULL) {
		exec->recordings[index].recHead = (RecordList*)malloc(sizeof(struct RecordList));
		if (exec->recordings[index].recHead == NULL) return -1;
		// the first element should never have a next
		exec->recordings[index].recHead->next = NULL;
	}
	else {
		// there is a head, and possibly elements following the head
		// create a new element that prepends the head
		RecordList* entry = (RecordList*)malloc(sizeof(struct RecordList));
		if (entry == NULL) return -1;

		// 進行鏈結，且recHead永遠是最新的呼叫
		entry->next = exec->recordings[index].recHead;
		exec->recordings[index].recHead = entry;
	}

	// 設置recHead為傳入的rec
	exec->recordings[index].recHead->rec = *rec;
	return 1;
}

void PrintRecordList(Execution* exec, LONG index)
{
	printf("\n**** System Call Recordings ****\n");

	RecordList* loop = exec->recordings[index].recHead;
	while (loop != NULL) {
		switch (loop->rec.type) {
		case CTX_NONE:
			printf("[Recording] CALL %s (%llx) CTX {None}\n", DebugCallNames[(UINT)loop->rec.call], loop->rec.origin);
			break;
		case CTX_STR:
			printf("[Recording] CALL %s (%llx) CTX %ws\n", DebugCallNames[(UINT)loop->rec.call], loop->rec.origin, loop->rec.value.szCtx);
			break;
		case CTX_NUM:
			printf("[Recording] CALL %s (%llx) CTX %lu\n", DebugCallNames[(UINT)loop->rec.call], loop->rec.origin, loop->rec.value.dwCtx);
			break;
		}
		loop = loop->next;
	}
}

// 釋放Execution的記憶體
void DestroyExecution(Execution* exec)
{
	// 釋放Origins*的記憶體
	for (int i = 0; i < CALL_END; i++) {
		Origins* oloop = exec->CallOrigins[i];
		Origins* otemp = NULL;
		while (oloop != NULL) {
			otemp = oloop->next;
			free(oloop);
			oloop = otemp;
		}
	}

	RecordList* loop = NULL;
	RecordList* temp = NULL;

	// 釋放所有子線程的函數呼叫紀錄
	if (exec->RecIndex >= 0) {
		for (LONG index = 0; index <= exec->RecIndex; index++) {
			RecordList* loop = exec->recordings[index].recHead;
			RecordList* temp = NULL;
			while (loop != NULL) {
				temp = loop->next;
				free(loop);
				loop = temp;
			}
		}
	}

	free(exec);
}

// 新增要變異的內容到Frame的List中
int AddMutationToList(Recording* rec, MutationType* mutType, MutationValue* mutVal)
{
	// first element
	// 如果mutHead是空的，則創建一個新的Mutation
	if (frameCurr->mutHead == NULL) {
		frameCurr->mutHead = (Mutation*)malloc(sizeof(struct Mutation));
		if (frameCurr->mutHead == NULL) return -1;
		frameCurr->mutCurr = frameCurr->mutHead;
	}
	// head exists, curr points to last element
	else {
		frameCurr->mutCurr->next = (Mutation*)malloc(sizeof(struct Mutation));
		if (frameCurr->mutCurr->next == NULL) return -1;
		frameCurr->mutCurr = frameCurr->mutCurr->next;
	}

	// 將傳入的rec、mutType、mutVal設置到frameCurr的mutCurr中
	frameCurr->mutCurr->mutType = *mutType;
	if (mutVal != NULL) {
		frameCurr->mutCurr->mutValue = *mutVal;
	}
	frameCurr->mutCurr->rec = *rec;
	frameCurr->mutCurr->next = NULL;

	// 增加突變計數
	frameCurr->dwMutationCount++;

	return 1;
}

// 清空所以Mutation的記憶體
void DestroyMutationList()
{
	Mutation* loop = frameCurr->mutHead;
	Mutation* temp = NULL;
	while (loop != NULL) {
		temp = loop->next;
		free(loop);
		loop = temp;
	}
}

// 將突變資料傳送到管道
int TransferMutations(HANDLE pipe)
{
	DWORD dwWritten;
	BOOL ret;

	// 將突變計數傳送到pipe
	ret = WriteFile(pipe, &frameCurr->dwMutationCount, sizeof(frameCurr->dwMutationCount), &dwWritten, NULL);
	if (!ret) {
		printf("Transfer Handshake Failed\n");
		return -1;
	}

	// 遍歷frameCurr的所有突變，並將其傳送到pipe
	Mutation* loop = frameCurr->mutHead;
	while (loop != NULL) {
		ret = WriteFile(pipe, loop, sizeof(Mutation), &dwWritten, NULL);
		if (!ret) {
			printf("Transfer Mutation Failed\n");
			return -1;
		}
		loop = loop->next;
	}

	return 1;
}

// 回應線程
DWORD WINAPI ResponderThread(LPVOID lpvParam)
{
	HANDLE hPipe = (HANDLE)lpvParam;	// 接收一個命名管道(Named Pipe)的 handle 作為參數
	DWORD tid = GetCurrentThreadId();	// 取得當前執行緒的 ID

	// 安全地增加並獲取一個索引值
	LONG LocalRecIndex = InterlockedIncrement(&(frameCurr->currExec->RecIndex));
#ifdef __DEBUG_PRINT
	printf("This Responder Thread Gets Index: %ld\n", LocalRecIndex);
	printf("[RESPONDER %lu] Transfering mutations to new process.\n", tid);
#endif
	// 將frameCurr的每個突變資料傳送到管道，讓DLL可以接收
	TransferMutations(hPipe);

	// 檢查SyncEvent是否已設置，如果沒有，則繼續讀取管道的Mutation的Recording
	while (WaitForSingleObject(SyncEvent, 0) != WAIT_OBJECT_0) {
		Recording rec;
		DWORD dwRead;

		// 讀取管道的Mutation的Recording(從DLL來的)
		BOOL rd = ReadFile(hPipe, (void*)&rec, sizeof(rec), &dwRead, NULL);
		if (rd) {

			// 將讀取到的Recording加入到frameCurr的currExec的本地記錄中
			AddRecordToList(frameCurr->currExec, &rec, LocalRecIndex);

			// 檢查rec是否是CreateProcessInternalW這個Windows API
			if (rec.call == Call::cCreateProcessInternalW) {
#ifdef __DEBUG_PRINT
				printf("We found creation of PID: %u\n", rec.value.dwCtx);
#endif
				// 檢查是否超過上限(100)，並將其加入到pids陣列中
				if (pidptr < MAX_PIDS) {
					pids[pidptr] = rec.value.dwCtx;
					pidptr++;
				}
			}

			//printf("[RESPONDER %lu] Recv recording: %s\n", tid, DebugCallNames[rec.call]);
		}
		else {
			// 如果讀取失敗，則檢查錯誤碼
			// ReadFile failed, if it is because ERROR_BROKEN_PIPE, then the client disconnected.
			DWORD err = GetLastError();

			// 客戶端斷開連接
			if (err == ERROR_BROKEN_PIPE) {
#ifdef __DEBUG_PRINT
				printf("[RESPONDER %lu] No more reading, the client disconnected.\n", tid);
#endif
			}
			// 客戶端取消操作
			else if (err == ERROR_OPERATION_ABORTED) {
#ifdef __DEBUG_PRINT
				printf("[RESPONDER %lu] Cancelling ghost orphan child.\n", tid);
#endif
			}
			else {
				printf("[RESPONDER %lu] Unexpected fatal ReadFile error: %ld\n", tid, err);
			}
			break;
		}
	}
#ifdef __DEBUG_PRINT
	printf("[RESPONDER %lu] Shutting down gracefully.\n", tid);
#endif	

	// 關閉管道
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
	return 1;
}

// 監聽線程
DWORD WINAPI ListenerThread(LPVOID lpvParam)
{
	printf("[Enviral Launcher] Listener thread is active.\n");
	HANDLE InstancePipe = NULL;
	BOOL conn = FALSE;
	DWORD dwThreadId = 0;

	while (TRUE) {
		// 創建一個新的命名管道實例，雙向通信模式(PIPE_ACCESS_DUPLEX)、消息類型管道(PIPE_TYPE_MESSAGE)
		InstancePipe = CreateNamedPipeW(szPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 0, 0, 0, NULL);
		if (InstancePipe == NULL || InstancePipe == INVALID_HANDLE_VALUE) {
			fprintf(stderr, "Could not create named pipe\n");
			return 0;
		}

		// 等待客戶端連接(等待DLL連接)
		conn = ConnectNamedPipe(InstancePipe, NULL);
		if (!conn && GetLastError() != ERROR_PIPE_CONNECTED) {
			fprintf(stderr, "Could not connect named pipe\n");
			return 0;
		}
#ifdef __DEBUG_PRINT
		printf("[LISTENER] New client connection obtained!\n");
#endif
		// 判斷是否超過最大可用的回應線程(20)
		if (dwThreadCount >= MAX_CHILD) {
			printf("Exceeded max available responder threads!\n");
			continue;
		}

		// 創建響應線程，並存在hThreads陣列中，用dwThreadCount計數
		// 這個Responder
		hThreads[dwThreadCount] = CreateThread(NULL, 0, ResponderThread, (LPVOID)InstancePipe, 0, &dwThreadId);
		if (hThreads[dwThreadCount] == NULL) {
			fprintf(stderr, "Could not create responder thread\n");
			return 0;
		}
		dwThreadCount++;
	}

	return 1;
}

// 用於終止子進程
void NukeChildren(DWORD pid)
{
	DWORD i;

	// 創建進程快照
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return;

	// 初始化進程快照結構，用於進程枚舉
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
		return;

	do {
		for (i = 0; i < pidptr; i++) {
			// 如果找到子進程的PID，則終止此子進程
			if (pe32.th32ProcessID == pids[i]) {
#ifdef __DEBUG_PRINT
				printf("[MATCH]: Child Process Recorded PID: %u\n", pids[i]);
#endif
				// 用OpenProcess獲得子進程關閉的權限
				HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
				if (hProc != NULL) {
					// terminate
#ifdef __DEBUG_PRINT
					BOOL kill = TerminateProcess(hProc, 66);
					printf("Kill %u result: %d\n", pids[i], kill);
#else
					TerminateProcess(hProc, 0);
#endif
				}
#ifdef __DEBUG_PRINT
				else {
					printf("it appears we do not have sufficient access to terminate the process.\n");
				}
#endif
			}
		}

	} while (Process32Next(hProcessSnap, &pe32));

	// reset
	pidptr = 0;
	CloseHandle(hProcessSnap);
}

// 啟動目標進程並注入DLL
int LaunchTarget(char* target)
{
	// 將SyncEvent設定為未設置，以便讓線程繼續運行
	ResetEvent(SyncEvent); // threads will loop

	STARTUPINFOA si;		// 進程啟動訊息結構
	PROCESS_INFORMATION pi;	// 進程訊息結構
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// start process in suspended mode
	// 以暫停模式啟動目標進程
	if (!CreateProcessA(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		fprintf(stderr, "Could not create target process\n");
		return -1;
	}

	// problem
	// DLL注入，注意DLL的路徑(存在TARGET_DLL)
	// allocate memory for dll name(分配記憶體給dll路徑)
	size_t lendll = sizeof(TARGET_DLL); //strlen(TARGET_DLL);
	LPVOID dllname = VirtualAllocEx(pi.hProcess, NULL, lendll + 1, MEM_COMMIT, PAGE_READWRITE);
	if (dllname == NULL)
	{
		fprintf(stderr, "Could not allocate memory in target for dll name\n");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}

	// write dll name in target memory(寫入dll路徑到記憶體)
	if (!WriteProcessMemory(pi.hProcess, dllname, TARGET_DLL, lendll, NULL))
	{
		fprintf(stderr, "Could not write to target process memory for dll name\n");
		VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}

	// 獲取LoadLibraryA的函數地址，從kernel32.dll取得
	// get the kernel32 DLL module
	HMODULE k32 = GetModuleHandleA("kernel32.dll");
	if (k32 == NULL)
	{
		fprintf(stderr, "Could not obtain kernel32.dll handle\n");
		VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}

	// obtain pointer to LoadLibraryA()
	LPVOID pLoadLibraryA = GetProcAddress(k32, "LoadLibraryA");
	if (pLoadLibraryA == NULL)
	{
		fprintf(stderr, "Could not get address of LoadLibraryA\n");
		VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}

	// call LoadLibraryA() in the target process
	// 在目標進程創建一個新的線程，並在該線程中調用LoadLibraryA()來加載dll
	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryA, dllname, NULL, NULL);
	if (hThread == NULL)
	{
		fprintf(stderr, "Could not create thread in target process\n");
		VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}

	// wait for the new loader thread to finish
	// 等待新的加載線程結束
	DWORD wait = WaitForSingleObject(hThread, INFINITE); // INFINITE?
	if (wait == WAIT_FAILED)
	{
		fprintf(stderr, "Could not wait for loader thread\n");
		VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}

	// resume the original suspended target process (primary thread)
	// 恢復目標進程的主線程執行
	DWORD resume = ResumeThread(pi.hThread);
	if (resume == (DWORD)-1)
	{
		fprintf(stderr, "Could not resume execution of target process\n");
		return -1;
	}

	VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);

	// wait for target process to finish(等待目標進程結束)
	WaitForSingleObject(pi.hProcess, LAUNCH_TIME_LIMIT);

	// cease responder threads
	// 終止回應線程同步資料
	SetEvent(SyncEvent);
	for (DWORD j = 0; j < dwThreadCount; j++) {
		CancelSynchronousIo(hThreads[j]);
		CloseHandle(hThreads[j]);
	}
	// 重製dwThreadCount
	dwThreadCount = 0;

	// The SyncEvent will cancel the pipe communication, however the target process may still be running.
	TerminateProcess(pi.hProcess, 0);

	// 關閉所以的子進程
	NukeChildren(pi.dwProcessId);

	// Process has exited - check its exit code
	/*
	DWORD exitCode;
	GetExitCodeProcess(pi.hProcess, &exitCode);
	printf("Target process Exit code: %x (%lu)\n", exitCode, exitCode);

	if (exitCode == 1337) {
		printf("Program was running and got forcefully terminated on timeout.\n");
	}
	*/

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return 0;
}

// 比較2個呼叫是否是相同的，如果是相同的，就返回TRUE
BOOL IsRecordingIdentical(Recording* src, Recording* cmp)
{
	if (cmp == NULL) {
		return FALSE;
	}

	if (src->call == cmp->call) {
		if (src->type == cmp->type) { // always true probably
			if (src->type == CTX_NONE) {
				return TRUE;
			}
			else if (src->type == CTX_NUM) {
				// context match
				return src->value.dwCtx == cmp->value.dwCtx;
			}
			else if (src->type == CTX_STR) {
				// context match
				return (wcsncmp(src->value.szCtx, cmp->value.szCtx, MAX_CTX_LEN) == 0);
			}
		}
	}
	return FALSE;
}

Mutation* GetCurrentMutation()
{
	return frameCurr->mutCurr;
}

// 檢查Mutation是否已經存在
BOOL MutationExists(Recording* rec)
{
	Mutation* loop = frameCurr->mutHead;
	while (loop != NULL) {
		if (loop->rec.call == rec->call) {
			if (rec->type == CTX_NUM) {
				if (loop->rec.value.dwCtx == rec->value.dwCtx) {
					// context match
					return TRUE;
				}
			}
			else if (rec->type == CTX_STR) {
				if (wcsncmp(loop->rec.value.szCtx, rec->value.szCtx, MAX_CTX_LEN) == 0) {
					// context match
					return TRUE;
				}
			}
			else if (rec->type == CTX_NONE) {
				// call ID match
				return TRUE;
			}
		}
		loop = loop->next;
	}

	// frames backtracking: mutation(s) to skip
	// 檢查是否屬於要跳過的Mutation
	loop = frameCurr->skip;
	while (loop != NULL) {
		if (loop->rec.call == rec->call) {
			if (rec->type == CTX_NUM) {
				if (loop->rec.value.dwCtx == rec->value.dwCtx) {
					// context match
					return TRUE;
				}
			}
			else if (rec->type == CTX_STR) {
				if (wcsncmp(loop->rec.value.szCtx, rec->value.szCtx, MAX_CTX_LEN) == 0) {
					// context match
					return TRUE;
				}
			}
			else if (rec->type == CTX_NONE) {
				// call ID match
				return TRUE;
			}
		}
		loop = loop->next;
	}

	return FALSE;
}

// 顯示Call的呼叫次數
void PrintCallCounts(Execution* exec)
{
	ULONG tot = 0;
	printf("--------------- \"Coverage\" ---------------\n");
	for (long c = 0; c < CALL_END; c++) {
		if (exec->CallCounts[c] > 0) {
			printf("CallCount %s = %ld\n", DebugCallNames[c], exec->CallCounts[c]);
			tot += exec->CallCounts[c];
		}
	}
	printf("TotalAct %lu\n", tot);
}

// 初始化Execution
void InitExecution(Execution* exec, Execution* prev, Execution* next, BOOL skip)
{
	exec->RecIndex = (LONG)-1;	// 設定索引紀錄為-1
	// 清空呼叫計數和來源陣列
	memset((void*)exec->CallCounts, 0, sizeof(exec->CallCounts));
	memset((void*)exec->CallOrigins, 0, sizeof(exec->CallOrigins));

	// 清空本地函數呼叫紀錄陣列
	for (int i = 0; i < MAX_CHILD; i++) {
		exec->recordings[i].recCurr = NULL;
		exec->recordings[i].recHead = NULL;
	}
	exec->mutStore = NULL;	// 清空最後一次變異的指標
	exec->prev = prev;	// 設置上一次Execution，如果有的話
	// 如果prev不為空且不跳過，則將prev的下一個指向exec，進行完整的雙向鏈接
	if (prev != NULL && !skip) {
		prev->next = exec;
	}
	exec->next = next;	// 向下鏈結
}

void DestroyExecutionList(Execution* baseExec)
{
	Execution* eloop = baseExec;
	Execution* etemp = NULL;
	while (eloop != NULL) {
		etemp = eloop->next;
		DestroyExecution(eloop);
		eloop = etemp;
	}
}

// 判斷Call是否來自新的Origin
BOOL EvaluateOrigin(Execution* exec, int call, UINT64 origin)
{
	// 第一次新增來源
	if (exec->CallOrigins[call] == NULL) {
		// first origin observed
		exec->CallOrigins[call] = (Origins*)malloc(sizeof(struct Origins));
		if (exec->CallOrigins[call] == NULL) {
			return FALSE;
		}

		exec->CallOrigins[call]->origin = origin;
		exec->CallOrigins[call]->next = NULL;
		return TRUE;
	}
	else {
		// there are already 1 or more origins -> do they include the new origin?
		// 檢查是否為重複的來源，若是重複則返回FALSE
		Origins* loop = exec->CallOrigins[call];
		do {
			if (loop->origin == origin) {
				// origin is already known
				return FALSE;
			}
			loop = loop->next;
		} while (loop != NULL);

		// Origin not found, make it the new head.
		// 若是新的來源，則新增到CallOrigins的頭部
		Origins* newOrigin = (Origins*)malloc(sizeof(struct Origins));
		if (newOrigin == NULL) {
			return FALSE;
		}
		newOrigin->origin = origin;
		newOrigin->next = exec->CallOrigins[call];
		exec->CallOrigins[call] = newOrigin;
		return TRUE;
	}
	return FALSE;
}

// 計算UniqueCall的數量
BOOL GenerateUniqueCallcounts(Execution* exec)
{
	/*
		Idea: reduce the counts of calls that have the same origin.
		i.e., all calls to CallX from the same origin count as 1
		Because a mutation that changes a loop count or randomness is not 'gain'
		Essentially, we will be counting the amount of unique calls to each API.
	*/

	// 若exec的RecIndex >= 0，則至少有1個client成功連接recording
	if (exec->RecIndex >= 0) {
		// at least 1 client successfully connected for recordings
		// 遍歷每個client的recording
		for (LONG i = 0; i <= exec->RecIndex; i++) {
			RecordList* entry = exec->recordings[i].recHead;
			while (entry != NULL) {
				// 計算是否為新的Origin，若是則增加CallCounts
				if (EvaluateOrigin(exec, entry->rec.call, entry->rec.origin)) {
					// new origin stored. increment unique count 
					exec->CallCounts[entry->rec.call]++;
				}
				entry = entry->next;
			}
		}
		return TRUE;
	}
	return FALSE;
}

DWORD CalculatePureActivityCallGain(Execution* exec)
{
	DWORD PureActivity = 0;
	for (long c = CALL_SEPARATOR + 1; c < CALL_END; c++) {
		PureActivity += exec->CallCounts[c];
	}
	return PureActivity;
}

BOOL IsActivityGainExtended(Execution* exec)
{
	if (exec->prev == NULL) {
		return FALSE;
	}
	Execution* prev = exec->prev;

	int NetGain = 0;
	int PosGain = 0;
	int g = 0;
	for (long c = 0; c < CALL_END; c++) {
		g = exec->CallCounts[c] - prev->CallCounts[c];
		NetGain += g;
		if (g > 0) {
			PosGain += g;
		}
	}

	if (NetGain >= GAIN_THRESHOLD) {
		return TRUE;
	}
	else if (NetGain >= -5 && PosGain > GAIN_THRESHOLD) {
		return TRUE;
	}

	return FALSE;
}

// 計算活動增益
LONG CalculateActivityGain(Execution* exec)
{
	if (exec->prev == NULL) {
		return -1;
	}

	// Maybe something with Exit Codes and TerminateProcess
	// i.e., how did the process end? Naturally? Killed? Crashed?
	// was there a NtTerminateProcess before or after the mutation?


	// TODO: compare net negative gain with positive only to allow e.g. net -5 pos +5 (-10 +5)?

	Execution* prev = exec->prev;

	LONG AccumulatedGain = 0;
	LONG gain = 0;

	// 當前exec和上一個exec的CallCounts相減，得到增益，計算總合
	for (long c = 0; c < CALL_END; c++) {
		gain = exec->CallCounts[c] - prev->CallCounts[c];
#ifdef POSITIVE_GAIN_ONLY		
		if (gain > 0)
#endif		
		{
			AccumulatedGain += gain;
		}
	}

	return AccumulatedGain;
}

// 輸出Mutation到輸出文件
void PrintMutation(Mutation* mut, FILE* fp)
{
	fprintf(fp, "> %s\t", DebugCallNames[mut->rec.call]);
	if (mut->rec.type == CTX_NUM) {
		fprintf(fp, "%lu\n", mut->rec.value.dwCtx);
		switch (mut->mutType) {
		case MUT_FAIL: { fprintf(fp, "\t-> FORCEFAIL\n"); } break;
		case MUT_ALT_NUM: { fprintf(fp, "\t-> %d\n", mut->mutValue.nValue); } break;
		case MUT_RND_NUM: { fprintf(fp, "\t-> RANDOM\n"); } break;
		case MUT_HIDE: { fprintf(fp, "\t-> HIDE\n"); } break;
		}
	}
	else if (mut->rec.type == CTX_STR) {
		fprintf(fp, "%ws\n", mut->rec.value.szCtx);
		switch (mut->mutType) {
		case MUT_FAIL: { fprintf(fp, "\t-> FORCEFAIL\n"); } break;
		case MUT_ALT_STR: { fprintf(fp, "\t-> ALT: %ws\n", mut->mutValue.szValue); } break;
		case MUT_HIDE: { fprintf(fp, "\t-> HIDE\n"); } break;
		case MUT_SUCCEED: { fprintf(fp, "\t-> SUCCEED\n"); } break;
		case MUT_ALT_NUM: { fprintf(fp, "\t-> ALT: %lu\n", mut->mutValue.nValue); } break;
		}
	}
	else {
		fprintf(fp, "{NoCtx}\n");
		switch (mut->mutType) {
		case MUT_FAIL: { fprintf(fp, "\t-> FORCEFAIL\n"); } break;
		case MUT_SUCCEED: { fprintf(fp, "\t-> SUCCEED\n"); } break;
		case MUT_HIDE: { fprintf(fp, "\t-> HIDE\n"); } break;
		case MUT_RND_TUP: { fprintf(fp, "\t-> RANDOM_TUP\n"); } break;
		case MUT_RND_NUM: { fprintf(fp, "\t-> RANDOM_NUM\n"); } break;
		case MUT_ALT_NUM: { fprintf(fp, "\t-> ALT: %lu\n", mut->mutValue.nValue); } break;
		}
	}
}

// 輸出Recording到輸出文件
void PrintRecording(Recording* rec, FILE* fp)
{
	switch (rec->type) {
	case CTX_NONE:
		fprintf(fp, "[R#%llx]\t%s\t{None}\n", rec->origin, DebugCallNames[(UINT)rec->call]);
		break;
	case CTX_STR:
		if (IsPrintable(rec->value.szCtx))
			fprintf(fp, "[R#%llx]\t%s\t%ws\n", rec->origin, DebugCallNames[(UINT)rec->call], rec->value.szCtx);
		else
			fprintf(fp, "[R#%llx]\t%s\t{NP}\n", rec->origin, DebugCallNames[(UINT)rec->call]);
		break;
	case CTX_NUM:
		fprintf(fp, "[R#%llx]\t%s\t%lu\n", rec->origin, DebugCallNames[(UINT)rec->call], rec->value.dwCtx);
		break;
	}
}

int OutputMutationEffects(Execution* base, int phase)
{
	char FileName[MAX_PATH];
	strcpy_s(FileName, MAX_PATH, "EnviralOut_ph");
	char numm[2];
	numm[0] = '0' + phase;
	numm[1] = '\0';
	strcat_s(FileName, MAX_PATH, numm);
	strcat_s(FileName, MAX_PATH, ".txt");

	FILE* fp;
	if (fopen_s(&fp, FileName, "w+") != 0) {
		fprintf(stderr, "Could not create output effects file.\n");
		return -1;
	}

	fprintf(fp, "-------- Result: Gainful Execution Cycles (Phase %d) --------\n", phase);
	fprintf(fp, "#### Baseline Activity ####\n");
	int i;
	for (i = 0; i < CALL_END; i++) {
		if (base->CallCounts[i] > 0) {
			fprintf(fp, "> %s\t%d\n", DebugCallNames[i], base->CallCounts[i]);
		}
	}

	Execution* prev = base;
	Execution* loop = base->next;
	Mutation* mut;
	int cnt = 1;
	int diff = 0;
	while (loop != NULL) {
		if (loop->mutStore == NULL) {
			printf("No mutation stored in execution\n");
			break;
		}
		fprintf(fp, "\n#### Cycle: %d ####\n", cnt);
		fprintf(fp, "Pure Activity Score\t%lu\n", CalculatePureActivityCallGain(loop));
		fprintf(fp, "Mutation:\n");
		mut = frameCurr->mutHead;
		while (mut != loop->mutStore) {
			mut = mut->next;
		}

		PrintMutation(mut, fp);

		fprintf(fp, "Activity Delta:\n");
		for (i = 0; i < CALL_END; i++) {
			diff = loop->CallCounts[i] - prev->CallCounts[i];
			if (diff != 0) {
				fprintf(fp, "> %s\t%d\n", DebugCallNames[i], diff);
			}
		}

		cnt++;
		prev = loop;
		loop = loop->next;
	}

	// prev holds the final log
	if (prev != NULL) {
		if (prev->mutStore == NULL) {
			printf("No mutation stored in last execution\n");
			return 0;
		}
		fprintf(fp, "\n#### Final Execution ####\n");
		ULONG GainScore = 0;
		for (i = 0; i < CALL_END; i++) {
			diff = prev->CallCounts[i] - base->CallCounts[i];
			if (diff != 0) {
				GainScore += diff;
			}
		}
		fprintf(fp, "Pure Activity Score\t%lu\n", CalculatePureActivityCallGain(prev));
		fprintf(fp, "Gain Score\t%lu\n", GainScore);
		fprintf(fp, "Total Num. Processes\t%lu\n", prev->RecIndex + 1);

		fprintf(fp, "Final Mutations\t%lu\n", frameCurr->dwMutationCount);
		mut = frameCurr->mutHead;
		while (mut != prev->mutStore) {
			PrintMutation(mut, fp);
			mut = mut->next;
		}
		// mut now contains mutStore
		PrintMutation(mut, fp);

		fprintf(fp, "Final Activity Delta:\n");
		for (i = 0; i < CALL_END; i++) {
			if (prev->CallCounts[i] > 0) {
				fprintf(fp, "> %s\t%d\n", DebugCallNames[i], prev->CallCounts[i]);
			}
		}

		// activity detailed log 
		fprintf(fp, "\nFinal Recording (Last-To-First):\n");
		for (LONG p = 0; p <= prev->RecIndex; p++) {
			fprintf(fp, "-- Process %ld --\n", p);
			RecordList* entry = prev->recordings[p].recHead;
			while (entry != NULL) {
				/*
				switch (entry->rec.type) {
				case CTX_NONE:
					fprintf(fp, "[R#%x]\t%s\t{None}\n", entry->rec.origin, DebugCallNames[(UINT)entry->rec.call]);
					break;
				case CTX_STR:
					fprintf(fp, "[R#%x]\t%s\t%ws\n", entry->rec.origin, DebugCallNames[(UINT)entry->rec.call], entry->rec.value.szCtx);
					break;
				case CTX_NUM:
					fprintf(fp, "[R#%x]\t%s\t%lu\n", entry->rec.origin, DebugCallNames[(UINT)entry->rec.call], entry->rec.value.dwCtx);
					break;
				}
				*/
				PrintRecording(&entry->rec, fp);
				entry = entry->next;
			}
		}
	}

	// baseline recording (to see diff) 
	fprintf(fp, "\nBaseline Recording (Last-To-First):\n");
	for (LONG p = 0; p <= base->RecIndex; p++) {
		fprintf(fp, "-- Process %ld --\n", p);
		RecordList* bentry = base->recordings[p].recHead;
		while (bentry != NULL) {
			/*
			switch (bentry->rec.type) {
			case CTX_NONE:
				fprintf(fp, "[R#%x]\t%s\t{None}\n", bentry->rec.origin, DebugCallNames[(UINT)bentry->rec.call]);
				break;
			case CTX_STR:
				fprintf(fp, "[R#%x]\t%s\t%ws\n", bentry->rec.origin, DebugCallNames[(UINT)bentry->rec.call], bentry->rec.value.szCtx);
				break;
			case CTX_NUM:
				fprintf(fp, "[R#%x]\t%s\t%lu\n", bentry->rec.origin, DebugCallNames[(UINT)bentry->rec.call], bentry->rec.value.dwCtx);
				break;
			}
			*/
			PrintRecording(&bentry->rec, fp);
			bentry = bentry->next;
		}
	}

	fclose(fp);
	return 1;
}

// 輸出階段1的實驗結果
int OutputExperimentPhase1(Execution* base, char* path, DWORD b1, DWORD b2, DWORD b3, Execution** postExec)
{
	// 取得3次執行
	Execution* exec1 = postExec[0];
	Execution* exec2 = postExec[1];
	Execution* exec3 = postExec[2];

	// Output: Baseline recording vs Mutate-All recording
	// 設置輸出文件的路徑
	char FileName[MAX_PATH];
	strcpy_s(FileName, LOG_PATH); // C:\ph2\ph2_ -> D:\ for VM
	char* target = PathFindFileNameA(path);
	strcat_s(FileName, target);
	strcat_s(FileName, ".txt");

	FILE* fp;
	if (fopen_s(&fp, FileName, "w+") != 0) {
		fprintf(stderr, "Could not create output effects file.\n");
		return -1;
	}
	if (fp == NULL) return -1;

	fprintf(fp, "### Experiment Phase 1 Output ###\n");
	fflush(stdout);

	// 檢查3次執行都不為空
	if (exec1 == NULL || exec2 == NULL || exec3 == NULL) {
		fprintf(fp, "[!!] FATAL ERROR - base:%p exec1:%p exec2:%p exec3:%p\n", base, exec1, exec2, exec3);

		fflush(fp);
		fclose(fp);
		return -1;
	}

	// 加總全部的UniqueCall
	UINT PostAct[3] = { 0 };
	for (UINT j = 0; j < CALL_END; j++) {
		PostAct[0] += postExec[0]->CallCounts[j];
		PostAct[1] += postExec[1]->CallCounts[j];
		PostAct[2] += postExec[2]->CallCounts[j];
	}

	// 選擇有最大的UniqueCall(活動量最大)的Execution作為next
	UINT select = 0;
	if (PostAct[1] > PostAct[0] && PostAct[1] >= PostAct[2]) {
		select = 1;
	}
	else if (PostAct[2] > PostAct[0] && PostAct[2] >= PostAct[1]) {
		select = 2;
	}
	Execution* next = postExec[select];

	// now we can compare base vs. next

	int ActivityGain = 0;
	int BaseAct = 0;
	int NextAct = 0;
	float RelActGain = 0.0f;
	int i;
	for (i = 0; i < CALL_END; i++) {
		BaseAct += base->CallCounts[i];
		NextAct += next->CallCounts[i];
	}
	// 計算是否有活動量的增加，存在ActicityGain中
	ActivityGain = NextAct - BaseAct;


	// 計算RelActGain
	if (BaseAct != 0)
		RelActGain = ((float)NextAct / BaseAct) * 100.0f;

	// note that our gains are in _unique_ calls, not total calls. 
	// and only a selected subset of calls is recorded.
	fprintf(fp, "BaseActivity\t%d\n", BaseAct);
	fprintf(fp, "NextActivity\t%d\n", NextAct);
	fprintf(fp, "ActivityGain\t%d\n", ActivityGain);
	fprintf(fp, "RelActivityGain\t%.2f\n", RelActGain);
	fprintf(fp, "BaseNumProc\t%d\n", base->RecIndex + 1);
	fprintf(fp, "NextNumProc\t%d\n", next->RecIndex + 1);

	// Baseline comparison counts
	fprintf(fp, "Baseline1\t%u\n", b1);
	fprintf(fp, "Baseline2\t%u\n", b2);
	fprintf(fp, "Baseline3\t%u\n", b3);

	fprintf(fp, "Postline1\t%u\n", PostAct[0]);
	fprintf(fp, "Postline2\t%u\n", PostAct[1]);
	fprintf(fp, "Postline3\t%u\n", PostAct[2]);

	// callcounts base, next & delta
	fprintf(fp, "\n--CallCountsBaseline--:\n");
	for (i = 0; i < CALL_END; i++) {
		if (base->CallCounts[i] > 0) {
			fprintf(fp, "%s\t%d\n", DebugCallNames[i], base->CallCounts[i]);
		}
	}

	fprintf(fp, "\n--CallCountsMutated--:\n");
	for (i = 0; i < CALL_END; i++) {
		if (next->CallCounts[i] > 0) {
			fprintf(fp, "%s\t%d\n", DebugCallNames[i], next->CallCounts[i]);
		}
	}

	// 輸出base和next同一個Call的數量差異
	fprintf(fp, "\n--CallCountsDelta--:\n");
	int diff = 0;
	for (i = 0; i < CALL_END; i++) {
		diff = next->CallCounts[i] - base->CallCounts[i];
		if (diff != 0) {
			fprintf(fp, "%s\t%d\n", DebugCallNames[i], diff);
		}
	}

	// recordings base & next
	fprintf(fp, "\n--RecordingBaseline(Last-To-First)--:\n");
	for (LONG p = 0; p <= base->RecIndex; p++) {
		fprintf(fp, ">> Process %ld:\n", p);
		RecordList* bentry = base->recordings[p].recHead;
		while (bentry != NULL) {
			PrintRecording(&bentry->rec, fp);
			bentry = bentry->next;
		}
	}

	fprintf(fp, "\n--RecordingMutated(Last-To-First):--\n");
	for (LONG p = 0; p <= next->RecIndex; p++) {
		fprintf(fp, ">> Process %ld:\n", p);
		RecordList* bentry = next->recordings[p].recHead;
		while (bentry != NULL) {
			PrintRecording(&bentry->rec, fp);
			bentry = bentry->next;
		}
	}

	fclose(fp);
	return 1;
}

// 輸出階段2的實驗結果，比較Baseline和ResponsiveMutate的結果
int OutputExperimentPhase2(Execution* base, Execution* last, char* path, DWORD b1, DWORD b2, DWORD b3, int MutGenExit)
{
	// base is the first execution (baseline)
	// the last execution did not result in any new mutations being created

	// Output: Baseline recording vs Responsive-Mutate-All recording
	char FileName[MAX_PATH];
	strcpy_s(FileName, LOG_PATH2); // C:\ph2\ph2_ -> D:\ for VM
	char* target = PathFindFileNameA(path);
	strcat_s(FileName, target);
	strcat_s(FileName, ".txt");

	FILE* fp;
	if (fopen_s(&fp, FileName, "w+") != 0) {
		fprintf(stderr, "Could not create output effects file.\n");
		return -1;
	}
	if (fp == NULL) return -1;

	fprintf(fp, "### Experiment Phase 2 Output ###\n");
	fflush(fp);

	if (last == NULL || base == last) {
		fprintf(fp, "[!!] FATAL ERROR - base:%p last:%p\n", base, last);

		// Baseline comparison counts
		fprintf(fp, "Baseline1\t%u\n", b1);
		fprintf(fp, "Baseline2\t%u\n", b2);
		fprintf(fp, "Baseline3\t%u\n", b3);

		// important metric for minimal set creation
		fprintf(fp, "MutationCount\t%d\n", frameBest->dwMutationCount);

		fprintf(fp, "\n--CallCountsBaseline--:\n");
		for (int i = 0; i < CALL_END; i++) {
			if (base->CallCounts[i] > 0) {
				fprintf(fp, "%s\t%d\n", DebugCallNames[i], base->CallCounts[i]);
			}
		}

		fprintf(fp, "\n--RecordingBaseline(Last-To-First):--:\n");
		for (LONG p = 0; p <= base->RecIndex; p++) {
			fprintf(fp, ">> Process %ld:\n", p);
			RecordList* bentry = base->recordings[p].recHead;
			while (bentry != NULL) {
				PrintRecording(&bentry->rec, fp);
				bentry = bentry->next;
			}
		}
		fflush(fp);
		fclose(fp);
		return -1;
	}

	// the most interesting metric is the difference in activity between last and base
	int ActivityGain = 0;
	int BaseAct = 0;
	int NextAct = 0;
	float RelActGain = 0.0f;
	float RelPureActGain = 0.0f;
	int i;
	for (i = 0; i < CALL_END; i++) {
		BaseAct += base->CallCounts[i];
		NextAct += last->CallCounts[i];
		ActivityGain += (last->CallCounts[i] - base->CallCounts[i]);
	}
	if (BaseAct != 0)
		RelActGain = ((float)NextAct / BaseAct) * 100.0f;

	DWORD BasePureAct = CalculatePureActivityCallGain(base);
	DWORD NextPureAct = CalculatePureActivityCallGain(last);
	if (BasePureAct != 0)
		RelPureActGain = ((float)NextPureAct / BasePureAct) * 100.0f;

	// note that our gains are in _unique_ calls, not total calls. 
	// and only a selected subset of calls is recorded.
	fprintf(fp, "BaseActivity\t%d\n", BaseAct);
	fprintf(fp, "NextActivity\t%d\n", NextAct);
	fprintf(fp, "ActivityGain\t%d\n", ActivityGain);
	fprintf(fp, "RelActivityGain\t%.2f\n", RelActGain);
	fprintf(fp, "BasePureActivity\t%lu\n", BasePureAct);
	fprintf(fp, "NextPureActivity\t%lu\n", NextPureAct);
	fprintf(fp, "RelPureActivity\t%.2f\n", RelPureActGain);
	fprintf(fp, "BaseNumProc\t%d\n", base->RecIndex + 1);
	fprintf(fp, "NextNumProc\t%d\n", last->RecIndex + 1);

	// Baseline comparison counts
	fprintf(fp, "Baseline1\t%u\n", b1);
	fprintf(fp, "Baseline2\t%u\n", b2);
	fprintf(fp, "Baseline3\t%u\n", b3);

	// important metric for minimal set creation
	fprintf(fp, "MutationCount\t%d\n", frameCurr->dwMutationCount);


	// 計算所有的Execution數量
	Execution* loopcnt = base;
	int execcnt = 0;
	while (loopcnt != NULL) {
		execcnt++;
		loopcnt = loopcnt->next;
	}
	fprintf(fp, "ExecutionCount\t%d\n", execcnt);
	fprintf(fp, "ExitCode\t%d\n", MutGenExit);

	// print all mutations
	fprintf(fp, "\nFinalMutationSet:\n");
	Mutation* mutLoop = frameCurr->mutHead;
	while (mutLoop != NULL) {
		PrintMutation(mutLoop, fp);
		mutLoop = mutLoop->next;
	}

	// then after that we can report the consecutive activity increases of executions
	Execution* prev = base;
	Execution* loop = base->next;
	Mutation* lastMut = NULL;
	mutLoop = NULL;
	int count = 1;
	LONG diff = 0;
	while (loop != NULL) {
		fprintf(fp, "\n>> Execution Response %d\n", count);

		// gain score
		ActivityGain = 0;
		for (i = 0; i < CALL_END; i++) {
			ActivityGain += (loop->CallCounts[i] - prev->CallCounts[i]);
		}
		fprintf(fp, "MutationActivityGain\t%d\n", ActivityGain);

		// all mutations up to and incl mutstore were applied to the curr exec
		if (lastMut == NULL) { // no prev mut
			mutLoop = frameCurr->mutHead;
		}
		else { // prev mut inc.
			mutLoop = lastMut->next;
		}

		// 輸出Exec的所有Mutation，並將最後一次的Mutation記錄下來到lastMut
		if (mutLoop != NULL) {
			fprintf(fp, "Applied Mutations:\n");
			while (TRUE) {
				PrintMutation(mutLoop, fp);
				if (mutLoop == loop->mutStore) {
					break;
				}
				// case for if loop->mutStore is NULL, the loop breaks too late otherwise.
				if (mutLoop->next == NULL) {
					break;
				}
				mutLoop = mutLoop->next;
			}
			lastMut = mutLoop;
		}


		fprintf(fp, "Activity Delta:\n");
		for (i = 0; i < CALL_END; i++) {
			diff = loop->CallCounts[i] - prev->CallCounts[i];
			if (diff != 0) {
				fprintf(fp, "%s\t%d\n", DebugCallNames[i], diff);
			}
		}
		count++;
		prev = loop;
		loop = loop->next;
	}

	// print the baseline callcounts
	fprintf(fp, "\n--CallCountsBaseline--:\n");
	for (i = 0; i < CALL_END; i++) {
		if (base->CallCounts[i] > 0) {
			fprintf(fp, "%s\t%d\n", DebugCallNames[i], base->CallCounts[i]);
		}
	}

	// print the final callcounts 
	fprintf(fp, "\n--CallCountsFinal--:\n");
	for (i = 0; i < CALL_END; i++) {
		if (last->CallCounts[i] > 0) {
			fprintf(fp, "%s\t%d\n", DebugCallNames[i], last->CallCounts[i]);
		}
	}

	// recordings base & next
	ULONG BaseRecordingCnt = 0;
	fprintf(fp, "\n--RecordingBaseline(Last-To-First):--:\n");
	for (LONG p = 0; p <= base->RecIndex; p++) {
		fprintf(fp, ">> Process %ld:\n", p);
		RecordList* bentry = base->recordings[p].recHead;
		while (bentry != NULL) {
			PrintRecording(&bentry->rec, fp);
			BaseRecordingCnt++;
			bentry = bentry->next;
		}
	}
	fprintf(fp, "BaseRecordingCnt\t%lu\n", BaseRecordingCnt);

	ULONG LastRecordingCnt = 0;
	fprintf(fp, "\n--RecordingLast(Last-To-First):--\n");
	for (LONG p = 0; p <= last->RecIndex; p++) {
		fprintf(fp, ">> Process %ld:\n", p);
		RecordList* bentry = last->recordings[p].recHead;
		while (bentry != NULL) {
			PrintRecording(&bentry->rec, fp);
			LastRecordingCnt++;
			bentry = bentry->next;
		}
	}
	fprintf(fp, "LastRecordingCnt\t%lu\n", LastRecordingCnt);

	fclose(fp);
	return 1;
}


int OutputExperimentPhase3(Execution* base, Execution* first, Execution* last, char* path, DWORD b1, DWORD b2, DWORD b3, ULONG cycles, int exit, BackTrackInfo* BT, ULONG volapplied)
{
	// Output: Baseline recording vs Responsive-Mutate-All recording
	char FileName[MAX_PATH];
	strcpy_s(FileName, LOG_PATH3); // C:\ph3\ph3_ -> D:\ for VM
	char* target = PathFindFileNameA(path);
	strcat_s(FileName, target);
	strcat_s(FileName, ".txt");

	FILE* fp;
	if (fopen_s(&fp, FileName, "w+") != 0) {
		fprintf(stderr, "Could not create output effects file.\n");
		return -1;
	}
	if (fp == NULL) return -1;

	fprintf(fp, "### Experiment Phase 3 Output ###\n");
	fflush(fp);

	if (last == NULL || first == NULL || (base == last)) {
		fprintf(fp, "[!!] FATAL ERROR - base:%p first:%p last:%p\n", base, first, last);

		// Baseline comparison counts
		fprintf(fp, "Baseline1\t%u\n", b1);
		fprintf(fp, "Baseline2\t%u\n", b2);
		fprintf(fp, "Baseline3\t%u\n", b3);

		// important metric for minimal set creation
		fprintf(fp, "MutationCount\t%d\n", frameBest->dwMutationCount);
		fprintf(fp, "VolatileCount\t%lu\n", volapplied);
		fprintf(fp, "CycleCount\t%lu\n", cycles);
		fprintf(fp, "LoopExitCode\t%d\n", exit);

		fprintf(fp, "\n--CallCountsBaseline--:\n");
		for (int i = 0; i < CALL_END; i++) {
			if (base->CallCounts[i] > 0) {
				fprintf(fp, "%s\t%d\n", DebugCallNames[i], base->CallCounts[i]);
			}
		}

		fprintf(fp, "\n--RecordingBaseline(Last-To-First):--:\n");
		for (LONG p = 0; p <= base->RecIndex; p++) {
			fprintf(fp, ">> Process %ld:\n", p);
			RecordList* bentry = base->recordings[p].recHead;
			while (bentry != NULL) {
				PrintRecording(&bentry->rec, fp);
				bentry = bentry->next;
			}
		}
		fflush(fp);
		fclose(fp);
		return -1;
	}

	// base is the first execution (baseline)
	// the last execution did not result in any new mutations being created

	// important: base does not have a next, since it scopes across frames
	// however, now that we have finished and are resorting to output
	// it should be safe to set first as the next of base
	// if more output is to be generated of different frames, then do not do this.

	base->next = first;

	// the most interesting metric is the difference in activity between last and base
	LONG ActivityGain = 0;
	int BaseAct = 0;
	int NextAct = 0;
	float RelActGain = 0.0f;
	float RelPureActGain = 0.0f;
	int i;
	for (i = 0; i < CALL_END; i++) {
		BaseAct += base->CallCounts[i];
		NextAct += last->CallCounts[i];
		ActivityGain += (last->CallCounts[i] - base->CallCounts[i]);
	}
	if (BaseAct != 0)
		RelActGain = ((float)NextAct / BaseAct) * 100.0f;

	DWORD BasePureAct = CalculatePureActivityCallGain(base);
	DWORD NextPureAct = CalculatePureActivityCallGain(last);
	if (BasePureAct != 0)
		RelPureActGain = ((float)NextPureAct / BasePureAct) * 100.0f;

	// note that our gains are in _unique_ calls, not total calls. 
	// and only a selected subset of calls is recorded.
	fprintf(fp, "BaseActivity\t%d\n", BaseAct);
	fprintf(fp, "NextActivity\t%d\n", NextAct);
	fprintf(fp, "ActivityGain\t%d\n", ActivityGain);
	fprintf(fp, "RelActivityGain\t%.2f\n", RelActGain);
	fprintf(fp, "BasePureActivity\t%lu\n", BasePureAct);
	fprintf(fp, "NextPureActivity\t%lu\n", NextPureAct);
	fprintf(fp, "RelPureActivity\t%.2f\n", RelPureActGain);
	fprintf(fp, "BaseNumProc\t%d\n", base->RecIndex + 1);
	fprintf(fp, "NextNumProc\t%d\n", last->RecIndex + 1);

	// Baseline comparison counts
	fprintf(fp, "Baseline1\t%u\n", b1);
	fprintf(fp, "Baseline2\t%u\n", b2);
	fprintf(fp, "Baseline3\t%u\n", b3);

	// important metric for minimal set creation
	fprintf(fp, "MutationCount\t%d\n", frameBest->dwMutationCount);
	fprintf(fp, "VolatileCount\t%lu\n", volapplied);
	fprintf(fp, "CycleCount\t%lu\n", cycles);
	fprintf(fp, "LoopExitCode\t%d\n", exit);

	fflush(fp);

	/*
	exit 0 = time limit expired
	exit 1 = no volatile mutations could be created in the new execution
	exit 2 = no next unidentical recording can be found to mutate
	*/

	Execution* loopcnt = base;
	int execcnt = 0;
	while (loopcnt != NULL) {
		execcnt++;
		loopcnt = loopcnt->next;
	}
	fprintf(fp, "ExecutionCount\t%d\n", execcnt);

	fprintf(fp, "BackTrackTotal\t%u\n", BT->BackTrackAttempts);
	fprintf(fp, "BackTrackKept\t%u\n", BT->BackTrackKept);
	fprintf(fp, "BackTrackInitAct\t%u\n", BT->InitAct);

	// print all mutations
	fprintf(fp, "\nFinalMutationSet:\n");
	Mutation* mutLoop = frameBest->mutHead;
	while (mutLoop != NULL) {
		PrintMutation(mutLoop, fp);
		mutLoop = mutLoop->next;
	}

	// then after that we can report the consecutive activity increases of executions
	Execution* prev = base;
	Execution* loop = base->next;
	Mutation* lastMut = NULL;
	mutLoop = NULL;
	int count = 1;
	LONG diff = 0;
	DWORD PosGain = 0;
	int tempg = 0;
	while (loop != NULL) {
		fprintf(fp, "\n>> Execution Response %d\n", count);
		// gain score
		ActivityGain = 0;
		PosGain = 0;
		for (i = 0; i < CALL_END; i++) {
			tempg = (loop->CallCounts[i] - prev->CallCounts[i]);
			ActivityGain += tempg;
			if (tempg > 0) {
				PosGain += tempg;
			}

		}
		fprintf(fp, "MutationActivityGain\t%d\t%d\n", ActivityGain, PosGain);
		// all mutations up to and incl mutstore were applied to the curr exec
		if (lastMut == NULL) { // no prev mut
			mutLoop = frameBest->mutHead;
		}
		else { // prev mut inc.
			mutLoop = lastMut->next;
		}

		if (mutLoop != NULL) {
			fprintf(fp, "Applied Mutations:\n");
			while (TRUE) {
				PrintMutation(mutLoop, fp);
				if (mutLoop == loop->mutStore) {
					break;
				}
				// case for if loop->mutStore is NULL, the loop breaks too late otherwise.
				if (mutLoop->next == NULL) {
					break;
				}
				mutLoop = mutLoop->next;
			}
			lastMut = mutLoop;
		}

		fprintf(fp, "Activity Delta:\n");
		for (i = 0; i < CALL_END; i++) {
			diff = loop->CallCounts[i] - prev->CallCounts[i];
			if (diff != 0) {
				fprintf(fp, "%s\t%d\n", DebugCallNames[i], diff);
			}
		}
		count++;
		prev = loop;
		loop = loop->next;
	}

	// print the baseline callcounts
	fprintf(fp, "\n--CallCountsBaseline--:\n");
	for (i = 0; i < CALL_END; i++) {
		if (base->CallCounts[i] > 0) {
			fprintf(fp, "%s\t%d\n", DebugCallNames[i], base->CallCounts[i]);
		}
	}

	// print the final callcounts 
	fprintf(fp, "\n--CallCountsFinal--:\n");
	for (i = 0; i < CALL_END; i++) {
		if (last->CallCounts[i] > 0) {
			fprintf(fp, "%s\t%d\n", DebugCallNames[i], last->CallCounts[i]);
		}
	}

	// recordings base & next
	ULONG BaseRecordingCnt = 0;
	fprintf(fp, "\n--RecordingBaseline(Last-To-First):--:\n");
	for (LONG p = 0; p <= base->RecIndex; p++) {
		fprintf(fp, ">> Process %ld:\n", p);
		RecordList* bentry = base->recordings[p].recHead;
		while (bentry != NULL) {
			PrintRecording(&bentry->rec, fp);
			BaseRecordingCnt++;
			bentry = bentry->next;
		}
	}
	fprintf(fp, "BaseRecordingCnt\t%lu\n", BaseRecordingCnt);

	ULONG LastRecordingCnt = 0;
	fprintf(fp, "\n--RecordingLast(Last-To-First):--\n");
	for (LONG p = 0; p <= last->RecIndex; p++) {
		fprintf(fp, ">> Process %ld:\n", p);
		RecordList* bentry = last->recordings[p].recHead;
		while (bentry != NULL) {
			PrintRecording(&bentry->rec, fp);
			LastRecordingCnt++;
			bentry = bentry->next;
		}
	}
	fprintf(fp, "LastRecordingCnt\t%lu\n", LastRecordingCnt);


	fclose(fp);
	return 1;
}

void InitFrame(Frame* frame)
{
	frame->firstExec = NULL;
	frame->currExec = NULL;
	frame->mutHead = NULL;
	frame->mutCurr = NULL;
	frame->dwMutationCount = 0;
	frame->skip = NULL;
	frame->act = 0;
}

void DestroyFrame(Frame* frame)
{
	Mutation* skip = frame->skip;
	Mutation* mutTemp = NULL;
	while (skip != NULL) {
		mutTemp = skip->next;
		free(skip);
		skip = mutTemp;
	}
	DestroyExecutionList(frame->firstExec);
	free(frame);
}

// 將Mutation複製到Frame的Skip中
int CopyMutationToSkip(Mutation* mut, Frame* frame)
{
	// 檢查frame的skip是否為空，如果是空的，則初始化
	if (frame->skip == NULL) {
		frame->skip = (Mutation*)malloc(sizeof(struct Mutation));
		if (frame->skip == NULL) return -1;

		frame->skip->mutType = mut->mutType;
		frame->skip->mutValue = mut->mutValue;
		frame->skip->rec = mut->rec;
		frame->skip->next = NULL;
	}
	else {
		Mutation* loop = frame->skip;
		while (loop->next != NULL) {
			loop = loop->next;
		}

		loop->next = (Mutation*)malloc(sizeof(struct Mutation));
		if (loop->next == NULL) return -1;
		loop = loop->next;

		loop->mutType = mut->mutType;
		loop->mutValue = mut->mutValue;
		loop->rec = mut->rec;
		loop->next = NULL;
	}

	return 1;
}

// 執行探索性測試
int RunExploration(char* path, Execution* baseExec, ULONG* cycle, ULONG* volapplied)
{
	RecordList* vol = NULL;
	BOOL stablegain = FALSE;
	BOOL gainful = TRUE;
	LONG gain = 0;
	LONG recindex = 0;
	Execution* p3exec = NULL;
	Execution* temp = NULL;

	// 設置時間限制
	DWORD CurTime = timeGetTime(); // milliseconds
	DWORD EndTime = CurTime + MUTATE_TIME_LIMIT; // s * 1000 (30)
	int exit = 0;
	while (CurTime < EndTime) {
#ifdef __DEBUG_PRINT
		printf("PH3: Cycle %d\n", *cycle);
#endif
		if (!stablegain) {
			// the prev exec was either: volatile+no stable gain, or stable
			// generate stable mutations
			// 有穩定的突變，採用
			if (gainful && GenerateResponsiveMutationsAll(frameCurr->currExec)) {
				// the last exec was gainful (volatile+gain or stable)
#ifdef __DEBUG_PRINT
				printf("There are stable mutations to apply.\n");
#endif
				// there are stable mutations to apply
				vol = NULL;
				gainful = TRUE;
				recindex = 0;
			}
			else {
				// no stable mutations, try volatile
#ifdef __DEBUG_PRINT
				printf("No (new) stable mutations, try volatile.\n");
#endif
				// 嘗試生成新的Volatile突變，如果有生成就返回
				vol = GenerateResponsiveVolatileMutation(frameCurr->currExec, vol, &recindex);
				if (vol == NULL) {
					// no volatile mutations to create - exit
#ifdef __DEBUG_PRINT
					printf("No volatile mutations to create. Exit loop.\n");
#endif
					exit = 1;
					break;
				}
			}
		}
		else {
			// the previous volatile cycle already applied stable gain, run the next exec
			stablegain = FALSE;
		}

		// Create a new Execution instance
		p3exec = (Execution*)malloc(sizeof(struct Execution));
		if (p3exec == NULL) return -1;

		// 紀錄每次的執行，方便進行回溯
		// 如果當前的執行是第一次執行，則將第一次執行設置為當前執行，並且初始化時base->next 不會被設置
		if (frameCurr->currExec == baseExec) {
			// set skip = TRUE, s.t. base->next is not set
			InitExecution(p3exec, frameCurr->currExec, NULL, TRUE);
			frameCurr->firstExec = p3exec;
		}
		else {
			InitExecution(p3exec, frameCurr->currExec, NULL, FALSE); // prev = curr, next = NULL
		}

		frameCurr->currExec = p3exec;
#ifdef __DEBUG_PRINT
		printf("Launching target with new mutation(s).\n");
#endif
		// Run next execution
		LaunchTarget(path);

		// Generate the equalized call counts
		GenerateUniqueCallcounts(frameCurr->currExec);

		// 如果是有成功產生Volatile突變
		if (vol) {
			stablegain = GenerateResponsiveMutationsAll(frameCurr->currExec);
			if (stablegain) {
				// volatile mutation is an instigator of new certain mutations
				// definitely keep the volatile mutation!
				// skip the next cycle's mutation generation, since it is already done now

				// 如果這個Volatile突變可以觸發新的Mutation，則表示是有效的，需要保留
				// 並且跳過下一個循環的突變生成，因為已經完成了
				gainful = TRUE;
				// reset recindex for next execution mutation search
				recindex = 0;
				vol = NULL;

				// +1 successful volatile mutation
				(*volapplied)++;

#ifdef __DEBUG_PRINT
				printf("[new!!] Volatile mutation resulted in stable gain. Keep.\n");
#endif
			}
			else {
				// consult the activity gain.
				// 若沒有產生新的Responsive Muatation，則計算其活動增益
				gain = CalculateActivityGain(frameCurr->currExec); // IsActivityGainExtended
				// 如果大於閥值就保留，否則丟棄
				if (gain >= GAIN_THRESHOLD) {
					// gainful mutation - keep
					gainful = TRUE;
					// reset recindex for next execution mutation search
					recindex = 0;
					vol = NULL;
					// +1 successfull volatile mutation
					(*volapplied)++;
#ifdef __DEBUG_PRINT
					printf("Gainful volatile mutation. Keep.\n");
#endif
				}
				else {
					// gainless mutation - discard
#ifdef __DEBUG_PRINT
					printf("Gainless volatile mutation. Discard/Reset.\n");
#endif
					// note that if we continue with the next execution, volatile mutation search resets.
					// however, the recordings are listed last-to-first, so the mutations will start with the new behavior.

					// 回溯到上一個Exec
					if (frameCurr->currExec == frameCurr->firstExec) {
						// the first exec has no prev.
						DestroyExecution(frameCurr->currExec);
						frameCurr->currExec = baseExec;
						frameCurr->firstExec = NULL;
					}
					else {
						// reset currExec back to prev
						temp = frameCurr->currExec->prev;
						DestroyExecution(frameCurr->currExec);
						frameCurr->currExec = temp;
						frameCurr->currExec->next = NULL;
					}

					/*
					temp = frameCurr->currExec;
					frameCurr->currExec = frameCurr->currExec->prev;
					frameCurr->currExec->next = NULL;
					free(temp);
					*/

					// reset mutation list 重製突變列表
					if (frameCurr->currExec->mutStore == NULL) {
						// no previous mutations, empty mutation list.
						// 沒有上一個突變，清空突變列表
#ifdef __DEBUG_PRINT
						printf("No previous mutations. Destroy mutation list.\n");
#endif
						DestroyMutationList();
						frameCurr->mutHead = NULL;
						frameCurr->mutCurr = NULL;
						frameCurr->dwMutationCount = 0;
					}
					else {
						// reset the mutations to what is stored in currExec
#ifdef __DEBUG_PRINT
						printf("Reset mutations to past mutStore.\n");
#endif
						// 將Frame儲存的Mutation回到上一個Exec的Mutation的狀態
						frameCurr->mutCurr = frameCurr->currExec->mutStore;

						// remove unwanted mutations
						Mutation* del = frameCurr->mutCurr->next;
						Mutation* tmp = NULL;
						while (del != NULL) {
							tmp = del->next;
							free(del);
							del = tmp;
							frameCurr->dwMutationCount--;
						}

						// reset the end of the mutations
						frameCurr->mutCurr->next = NULL;
					}

					// Find the next (unidentical!) volatile call to mutate
					// 當變異失效後，尋找下一個可用的變異點(往回找之前呼叫過的函數，因為是反向指針)
					BOOL NoCallsLeftToMutate = FALSE;
					RecordList* nextStart = vol->next;
					if (nextStart != NULL) {
						// 檢查是否為相同呼叫，避免對相同類型的呼叫重複變異
						while (IsRecordingIdentical(&vol->rec, &nextStart->rec)) {
#ifdef __DEBUG_PRINT
							printf("Finding Next Entry Point: %s is identical (skip!)\n", DebugCallNames[nextStart->rec.call]);
#endif
							// 發現這個Recording是相同的就再繼續往回找，直到找到不同的或是找不到(遇到NULL)
							nextStart = nextStart->next;
							if (nextStart == NULL) {
#ifdef __DEBUG_PRINT
								printf("The next entry point is NULL so that aint great\n");
#endif
								NoCallsLeftToMutate = TRUE;
								break;
							}
						}
					}
					else {
						// nextStart is NULL, no next call in this process
						NoCallsLeftToMutate = TRUE;
					}


					// if no calls can be found, we increase the RecIndex, as long as it is in bounds for RecIndex.
					// 如果沒有找到可變異的呼叫，就去尋找下一個進程(在RecIndex的範圍內允許)
					if (NoCallsLeftToMutate) {
#ifdef __DEBUG_PRINT
						printf("There are no calls left to mutate in the current RecIndex.\n");
#endif
						if (recindex + 1 > frameCurr->currExec->RecIndex) {
							// nothing left to mutate
#ifdef __DEBUG_PRINT
							printf("There are no other process recordings left to mutate. Exit loop.\n");
#endif
							exit = 2;
							break;
						}
						recindex++;
					}

					// starting point for next search (can be NULL)
					vol = nextStart;
					gainful = FALSE;
				}
			}
		}
		(*cycle)++;
		CurTime = timeGetTime();
	}
	return exit;
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: EnviralLauncher.exe <target application>\n");
		return -1;
	}
	//const char* source = "OpKey_check.exe";
	//char path[20];
	//strcpy_s(path, 20 ,source);
	char* path = argv[1];
	printf("[Enviral Launcher] Init: %s\n", path);

	frameCurr = (Frame*)malloc(sizeof(struct Frame));
	if (frameCurr == NULL) {
		return -1;
	}

	InitFrame(frameCurr);
	frameBest = frameCurr; // or NULL?

	// note that the base exec is shared across all the frames
	Execution* baseExec = (Execution*)malloc(sizeof(struct Execution));
	if (baseExec == NULL) {
		fprintf(stderr, "Could not allocate memory.\n");
		return -1;
	}

	// 初始化baseExec，InitExecution(當前exec, 上一個exec, 下一個exec, 是否跳過)
	InitExecution(baseExec, NULL, NULL, FALSE);

	// Initially, the current execution is the base execution
	frameCurr->currExec = baseExec;


	// 縣程的創建與管理
	// Create event to sync threads lifespan
	// 建立一個 Windows 事件同步物件（Event Synchronization Object），用於線程間的同步
	SyncEvent = CreateEventW(NULL, TRUE, FALSE, L"StopThreads");
	if (SyncEvent == NULL) {
		fprintf(stderr, "Could not create event.\n");
		return -1;
	}

	// Start thread to listen for new connections from (child) processes
	// 啟動一個線程，用於監聽來自子進程的新連接
	DWORD dwThreadId = 0;
	HANDLE hListenerThread = CreateThread(NULL, 0, ListenerThread, NULL, 0, &dwThreadId);
	if (hListenerThread == NULL) {
		fprintf(stderr, "Could not create listener thread\n");
		return -1;
	}

	// Create the baseline by executing the target
	LaunchTarget(path);
	//PrintRecordList(currExec, 0);

	// 計算UniqueCall的次數，以是否具相同的Origin為判斷標準
	GenerateUniqueCallcounts(frameCurr->currExec);

#ifdef __DEBUG_PRINT
	PrintCallCounts(frameCurr->currExec);
#endif

	/* Repeat Baseline Execution (Triple Baseline)*/
	Execution* base2 = (Execution*)malloc(sizeof(struct Execution));
	if (base2 == NULL) return -1;
	InitExecution(base2, NULL, NULL, FALSE);
	frameCurr->currExec = base2;
	LaunchTarget(path);
	GenerateUniqueCallcounts(frameCurr->currExec);
	Execution* base3 = (Execution*)malloc(sizeof(struct Execution));
	if (base3 == NULL) return -1;
	InitExecution(base3, NULL, NULL, FALSE);
	frameCurr->currExec = base3;
	LaunchTarget(path);
	GenerateUniqueCallcounts(frameCurr->currExec);

	// 在三次執行中，選擇最大的CallCounts
	DWORD base1cnt = 0, base2cnt = 0, base3cnt = 0;
	for (UINT c = 0; c < CALL_END; c++) {
		base1cnt += baseExec->CallCounts[c];
		base2cnt += base2->CallCounts[c];
		base3cnt += base3->CallCounts[c];
	}

	if (base2cnt > base1cnt && base2cnt >= base3cnt) {
		// base 2 biggest
		DestroyExecution(baseExec);
		DestroyExecution(base3);
		//free(baseExec);
		//free(base3);
		baseExec = base2;
		frameCurr->currExec = base2;
	}
	else if (base3cnt > base1cnt && base3cnt >= base2cnt) {
		// base 3 biggest
		DestroyExecution(baseExec);
		DestroyExecution(base2);
		//free(baseExec);
		//free(base2);
		baseExec = base3;
		frameCurr->currExec = base3;
	}
	else {
		// base 1 biggest
		DestroyExecution(base2);
		DestroyExecution(base3);
		//free(base2);
		//free(base3);
		frameCurr->currExec = baseExec;
	}

	// 評估階段，測試Preventive Mutations的效果
#ifdef __EVALUATION
	printf("----------------------__EVALUATION------------------------\n");
	printf("Baseline done -- generate responsive mutations.\n");
	//GenerateResponsiveMutationsAll(frameCurr->currExec);

	GenPreventiveMutationsAll();

	// Create a new Execution instance
	Execution* p3exec = (Execution*)malloc(sizeof(struct Execution));
	if (p3exec == NULL) return -1;

	// 初始化p3exec，但p3exec會被跳過
	InitExecution(p3exec, frameCurr->currExec, NULL, TRUE);
	frameCurr->firstExec = p3exec;
	frameCurr->currExec = p3exec;

	printf("Launching new mutated execution.\n");
	// Run next execution
	LaunchTarget(path);

	// Generate the equalized call counts
	GenerateUniqueCallcounts(frameCurr->currExec);

	PrintCallCounts(frameCurr->currExec);
	cout << "結束__EVALUATION" << endl;
#endif


#ifdef __EXPERIMENT_PHASE1
	/**** [START] Experiment Phase 1: Data Exploration ****/

	// Generate all the preventive mutations for the post-runs
	GenPreventiveMutationsAll();

	// three post mutation executions
	Execution* postExec[3] = { NULL };
	for (UINT i = 0; i < 3; i++) {
		// Create a new Execution instance
		postExec[i] = (Execution*)malloc(sizeof(struct Execution));
		// skip == TRUE, s.t. baseExec does not get a next
		InitExecution(postExec[i], baseExec, NULL, TRUE);
		frameCurr->currExec = postExec[i];

		// Run the target again, storing on the new execution instance
		LaunchTarget(path);

		// Generate the equalized call counts
		GenerateUniqueCallcounts(frameCurr->currExec);
	}

	// Output should use the largest post-mut for the gain, and also report the other posts for stability check
	OutputExperimentPhase1(baseExec, path, base1cnt, base2cnt, base3cnt, postExec);

	for (UINT i = 0; i < 3; i++) {
		DestroyExecution(postExec[i]);
	}
	/**** [END] Experiment Phase 1: Data Exploration ****/
#endif

#ifdef __EXPERIMENT_PHASE2
	/**** [START] Experiment Phase 2: Responsive Mutations ****/
	// Generate mutations in response to the finished execution

	BOOL MutGen = GenerateResponsiveMutationsAll(frameCurr->currExec);
	Execution* n2exec = NULL;
	DWORD CurTime = timeGetTime(); // milliseconds
	DWORD EndTime = CurTime + MUTATE_TIME_LIMIT;
	while (MutGen && CurTime < EndTime) {
		// Create a new Execution instance
		n2exec = (Execution*)malloc(sizeof(struct Execution));
		if (n2exec == NULL) return -1;
		InitExecution(n2exec, frameCurr->currExec, NULL, FALSE); // prev = curr, next = NULL
		frameCurr->currExec = n2exec;

		// Run the target again, storing on the new execution instance
		LaunchTarget(path);

		// Generate the equalized call counts
		GenerateUniqueCallcounts(frameCurr->currExec);

		// Generate new responsive mutations to the execution
		MutGen = GenerateResponsiveMutationsAll(frameCurr->currExec);
		CurTime = timeGetTime();
	}
	// Report the results
	OutputExperimentPhase2(baseExec, frameCurr->currExec, path, base1cnt, base2cnt, base3cnt, MutGen);
	/**** [END] Experiment Phase 2: Responsive Mutations ****/
#endif

#ifndef __EXPERIMENT_PHASE3
	/*
	Phase 3:
	Distinguish between stable mutations that should always be applied, and volatile mutations that require observation
	E.g.:
	- NtQueryValueKey("VBox") -> stable mutation should always be applied.
	- OpenMutex("Mutex123") -> volatile mutation that may or may not be relevant.
	- OpenFile("VBox") -> stable
	- OpenFile("File123") -> volatile
	There is no reason not to apply the stable mutations as response to the recording, since they are clearly evasive.
	After covering the stable mutations, try to apply 'interesting' volatile mutations, followed by random volatile mutations.

	1. Run baseline
	2. Apply stable mutations
	3. Run next execution
	4. Observe the call recordings of the execution:
		- If stable mutations are available, go to (2)
		- If no stable mutations are available, go to (5)
	5. Apply one (or more?) volatile mutation(s)
	6. Run the execution
	7. Observe the activity gain:
		- If the volatile mutation does not increase activity, discard
		- Else if the activity contains call recordings that involve stable mutations, go to (2)
		- Else go to (5)

	In phase 3 we try to extend upon phase 2 by introducing volatile mutations,
	combined with activity gain measurements.
	*/

	/**** [START] Experiment Phase 3: Volatile Mutations ****/
#ifdef __DEBUG_PRINT
	printf("------ finished running baselines ------\n");
#endif

	ULONG cycles = 0;
	ULONG volapplied = 0;
	int exit = RunExploration(path, baseExec, &cycles, &volapplied);
	frameBest = frameCurr; // just to make sure

	DWORD CurTime = timeGetTime(); // milliseconds
	DWORD EndTime = CurTime + BACKTRACK_TIME_LIMIT;

	// 設定回溯的資訊
	BackTrackInfo BT;
	BT.BackTrackAttempts = 0;
	BT.BackTrackKept = 0;
	BT.InitAct = 0;

#ifdef ENABLE_BACKTRACKING
	// store initial activity 
	// 紀錄一開始的活動數據(將當前Exec的CallCounts加總)
	for (int j = 0; j < CALL_END; j++) {
		BT.InitAct += frameBest->currExec->CallCounts[j];
	}
	frameBest->act = BT.InitAct;

	// Start BackTracking: loop finished. if there is a mutation, we try backtracking
	// 在時間限制內，且有可回溯的變異(mutHead != NULL)
	while (CurTime < EndTime && frameBest->mutHead != NULL) {

		// 新增一個Frame，並初始化
		frameCurr = (Frame*)malloc(sizeof(Frame));
		if (frameCurr == NULL) return -1;
		InitFrame(frameCurr);

		// since this is a new frame, the mutations are empty.
		// depending on where backtrack is pointing, we copy over mutations before the point or not.
		// note that if the backtracking results in a frame with better activity gains, it should become the main frame and mutation list

		/*
		NOTE: currently the backtracking does not have a memory.
		That is, if undoing a mutation of the original exploration and continuing the run yields better results,
		then this is the new best frame, and further mutations of the original exploration will not be undone.
		We could extend this if necessary.
		We can also perhaps repeat this process after exhausting all the mutations for backtracking
		*/

		// 第一次回溯的紀錄點設計
		if (mutBackTrack == NULL) {
			// this is the first backtrace
			// start the backtrace at the start of the best frame mutations
			// 從最佳Frame的第一個突變開始回溯
			mutBackTrack = frameBest->mutHead;
			// 將這個Mutation記錄到frameCurr的Skip中
			CopyMutationToSkip(mutBackTrack, frameCurr);
#ifdef __DEBUG_PRINT
			printf("[Backtrack setup] Skipping the FIRST mutation of prev frame:\n");
			PrintMutation(mutBackTrack, stdout);
#endif
		}
		else {
			// mutBackTrack points to a mutation in the list in the prev frame, where the backtracking has left off.
			// 找下一個作為回溯的突變
			mutBackTrack = mutBackTrack->next;
			if (mutBackTrack == NULL) {
#ifdef __DEBUG_PRINT
				printf("No more mutation to backtrack towards!\n");
				exit = 1;
#endif
				break;
			}
			// we move to the next mut to backtrack towards.
			// we _APPLY_ all mutations before the backtrack target, and skip the new backtrack target.
			Mutation* keep = frameBest->mutHead;
#ifdef __DEBUG_PRINT
			printf("[Backtrack setup] Copying some mutations to the next frame\n");
#endif			
			do {
				// copy mutations to the current frame
				AddMutationToList(&keep->rec, &keep->mutType, &keep->mutValue);
#ifdef __DEBUG_PRINT
				PrintMutation(keep, stdout);
#endif
				keep = keep->next;
			} while (keep != mutBackTrack && keep != NULL);
			CopyMutationToSkip(mutBackTrack, frameCurr);
#ifdef __DEBUG_PRINT
			printf("[Backtrack setup] Skipping the following mutation of prev frame:\n");
			PrintMutation(mutBackTrack, stdout);
#endif
		}

		// make sure the coverage is initially compared to the baseExec
		// 以baseExec為基底來測試
		frameCurr->currExec = baseExec;
		frameCurr->currExec->mutStore = NULL;
		RunExploration(path, baseExec, &cycles, &volapplied);

		// 回溯計數器增加
		BT.BackTrackAttempts++;

		LONG BestAct = 0;
		LONG CurrAct = 0;
		int i;
		// 計算frameCurr和frameBest的活動數量
		if (frameBest->act == 0) {
			// calc
			for (i = 0; i < CALL_END; i++) {
				CurrAct += frameCurr->currExec->CallCounts[i];
				BestAct += frameBest->currExec->CallCounts[i];
			}
		}
		else {
			// known
			BestAct = frameBest->act;
			for (i = 0; i < CALL_END; i++) {
				CurrAct += frameCurr->currExec->CallCounts[i];
			}
		}
#ifdef __DEBUG_PRINT //dbg
		printf("6 Activity Difference - Prev:%d Curr:%d\n", BestAct, CurrAct);
#endif
		// if this execution has better activity
		// becomes the new frame, set mutbacktrack back to null, continue

		// 比較兩者的活動數量，必較大的就設為frameBest，並刪除舊的frame
		if (CurrAct > BestAct) {
			// Count the occurrence of this transition
			// delete the old frame
#ifdef __DEBUG_PRINT
			printf("7 IN Keeping the new backtracked frame. More activity.\n");
#endif
			DestroyFrame(frameBest);
			frameBest = frameCurr;
			// reset mutBackTrack to start the backtracking exploration again
			mutBackTrack = NULL;
			frameCurr = NULL;
			BT.BackTrackKept++;
		}
		else {
			// the cur frame is not beneficial, discard it
#ifdef __DEBUG_PRINT
			printf("8 IN Discarding this frame, it is not beneficial.\n");
#endif
			DestroyFrame(frameCurr);
			frameCurr = NULL;
		}
		CurTime = timeGetTime();
	}
#endif

	OutputExperimentPhase3(baseExec, frameBest->firstExec, frameBest->currExec, path, base1cnt, base2cnt, base3cnt, cycles, exit, &BT, volapplied);

	// create "done.txt" to notify host system
	FILE* fp_done;
	if (fopen_s(&fp_done, DONE_PATH, "w") != 0) {
		fprintf(stderr, "Could not create done file.\n");
		return -1;
	}
	if (fp_done != NULL) {
		fprintf(fp_done, "OK");
		fflush(fp_done);
		fclose(fp_done);
	}

	// TODO: test backtracking on the following "highly evasive" samples from the 338 set:
	/*
	2440f7cb7f95f4284c3287b09e298627619f000738a5d7d6466f039cc1d73ba8
	03088d177ff4d57e58765da214100571d311195b073137bd36aed127ffb08362
	a28e93b4dd80839562cdd3f263fc1832ac57488ed7e3de66be667027ad35ed43
	0f6c0e4147c334bf04b7e2a83558bca1bbd7b78f0feb87dc11fe180d341933ce
	5f6eb83935da7c37d44f02145e77877ca0b251f515bae957b8e62ddbc04a4457
	780b7ad58ef84efabb707e69d965f748787dee6b969359f03174f72b1b069949
	4c9670af34c20d1d1d2b9847ee8ad86ad3803764fb0411ea097f5b4513f65f01
	1e1073cfae01f35e5377e89e2aa608546974547e2d0e9ab964032908d4357b25
	01933242c709f861f1bb7d19668a0c825cc790f8ab532eac9dcbaeedbff78dda
	6ee3368e696693d0a4d8f0aa16900c67b43c1065019dce83ac1e34fabf59fa41
	be1dfe8040b78e204e6323db17b6627969f2791c689d228cb3c08385f693cb26
	377b23171bd816b413581395bbb69f97728e8eccfb56502a22eba0e1c283c2c5
	485e76c2e7b023775b567189cdaa846c0f6e3febd817922b7795a53a7146d3cc
	450d7ee1a76f8bc096532ff34c6514351d061f281455ed6f46132370a256cb28
	1e6c8d049a497eb87c30984d777451076804c9b4ac22e711faebdd5eba2dbc31
	a4c98be42e7e19dbee70fcdda71cba5fbe8449fda0bf9eae60ecb71631b7ff56
	d2b5e01dbb42a8e971e5265f9d9d216fa68db9b1ba22a48f525978d87f510bb3
	7581c8dd06df2477c80b07dd82b7d871355e80a41b36850a67a1f13e0affe1ea
	9cce8fbe31afb0489d99a50638b55563abf5fb75781a2fe76f3503b134569e69
	e6f4470a069163e43ed9340558d493db0d8d1ce5f866d0fd4d4dc8e338776d2a
	461ea83d82437228d073e7b4c02470b4374081806a6ed716be1e85b1dfcb5032
	ca79305785ee42eff93fb2652688e2b81863ada41acdcb2c4f030ef0db1453e7
	86e41a77821cf6a9cca0deea8c5dbfb9a16b969e69f4ec8a532d3fd231b1dc1d
	046a64bd80d07e072c4ea7063d60a6e9657d20c8ee32fd4f472950e29b7f7931
	*/

	// for clean up
	frameCurr = frameBest;

	/**** [END] Experiment Phase 3: Volatile Mutations ****/
#endif // exp ph 3

// 用來測試的框架
#ifdef TEST_MODE_RETS
	// Generate a mutation based on the recorded baseline
	RecordList* callMutated = NULL;
	// 生成ResponsiveMustations
	callMutated = GenerateResponsiveMutations(currExec, NULL);
	if (callMutated == NULL) {
		printf("No Init Mutation could be generated (fatal)\n");
		return -1;
	}

	int execGain = 0;
	Execution* temp = NULL;
	for (int i = 2; i < 7; i++) { // 5
		// Create a new Execution instance
		// 生成新的Execution
		Execution* nexec = (Execution*)malloc(sizeof(struct Execution));
		if (nexec == NULL) return -1;
		InitExecution(nexec, currExec, NULL); // prev = curr, next = NULL
		currExec = nexec;

		printf("\n############### Execution %d ###############\n", i);
		// Run the target again, storing on the new execution instance
		LaunchTarget(path);

		// Get the call counts without loops
		GenerateUniqueCallcounts(currExec);

		// View the coverage
		PrintCallCounts(currExec);

		// View the difference in activity, calculate the information gain from the mutation.
		// 評估這個變異是否是有效的
		execGain = CalculateActivityGain(currExec);
		if (execGain >= 1) { // TODO: investigate activity gain threshold
			// There was a gain in activity caused by the last mutation
			printf("Last mutation was beneficial. Activity gain: %d\n", execGain);

			// Generate new mutations based on the current fresh execution
			callMutated = GenerateResponsiveMutations(currExec, NULL);
			if (callMutated == NULL) {
				printf("No Mutation could be generated (fatal)\n");
				break;
			}
		}
		else {
			// Insufficient gain. Reset currExec and remove last mutation.
			// 當突變是無效的話，就進行回溯
			printf("Last mutation was ineffective. Reverting state. Activity gain: %d\n", execGain);

			temp = currExec;
			currExec = currExec->prev;
			currExec->next = NULL;
			free(temp);

			if (currExec->mutStore == NULL) {
				// no previous mutations, empty mutation list.
				// 如果沒有之前的突變，就重置所有變異相關的指標
				printf("No previous mutations. Destroy mutation list.\n");
				DestroyMutationList();
				mutHead = NULL;
				mutCurr = NULL;
				dwMutationCount = 0;
			}
			else {
				// reset the mutations to what is stored in currExec
				// 回到之前的變異狀態
				printf("Reset mutations to past mutStore.\n");

				mutCurr = currExec->mutStore;

				// remove unwanted mutations
				Mutation* del = mutCurr->next;
				Mutation* tmp = NULL;
				while (del != NULL) {
					tmp = del->next;
					free(del);
					del = tmp;
					dwMutationCount--;
				}

				// reset the end of the mutations
				mutCurr->next = NULL;
			}

			// Generate new mutations based on the previous execution, continuing the mutation generation
			// Find the next (unidentical!) call to mutate
			// 尋找新的變異點
			BOOL NoCallsLeftToMutate = FALSE;
			RecordList* nextStart = callMutated->next;
			if (nextStart != NULL) {
				while (IsRecordingIdentical(&callMutated->rec, &nextStart->rec)) {
					printf("Finding Next Entry Point: %s is identical (skip!)\n", DebugCallNames[nextStart->rec.call]);
					nextStart = nextStart->next;
					if (nextStart == NULL) {
						NoCallsLeftToMutate = TRUE;
						break;
					}
				}
			}

			if (NoCallsLeftToMutate) {
				printf("[Finish] There are no calls left to mutate in the current setup.\n");
				break;
			}

			// if nextStart is NULL, then the mutation gen will start from the beginning again, restarting the whole thing
			// maybe the case where we break when nextStart == NULL should cancel the fuzzing altogether (no more mutations to be found?)
			callMutated = GenerateResponsiveMutations(currExec, nextStart);
			if (callMutated == NULL) {
				printf("No Mutation could be generated (fatal)\n");
				break;
			}
		}
	}

	OutputMutationEffects(baseExec, 0);
#endif

	// clean up
	DestroyMutationList();
	if (frameBest == frameCurr) {
		if (frameBest != NULL) DestroyFrame(frameBest);
	}
	else {
		if (frameBest != NULL) DestroyFrame(frameBest);
		if (frameCurr != NULL) DestroyFrame(frameCurr);
	}
	DestroyExecution(baseExec);
	CloseHandle(hListenerThread);

	return 1;
}