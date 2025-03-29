#pragma once

#define MAX_CHILD 20
#define MAX_PIDS 100

int AddMutationToList(Recording* rec, MutationType* mutType, MutationValue* mutVal);
BOOL MutationExists(Recording* rec);
Mutation* GetCurrentMutation();

struct RecordList {
	Recording rec;
	RecordList* next;
};

// per-instance recording (1 per connecting process)
// 管理每個處理程序的本地記錄
struct LocalRecording {
	// NOTE: this list grows backwards, the last call is the head.(記錄列表是反向增長的(最後的呼叫在頭部))
	RecordList* recHead = NULL;		// 記錄列表的頭部
	RecordList* recCurr = NULL;		// 當前記錄
};

// 追蹤 API 呼叫的來源
struct Origins {
	UINT64 origin;
	Origins* next;
};

// one execution instance
struct Execution {
	LocalRecording recordings[MAX_CHILD];	// 本地函數呼叫記錄陣列

	// volatile 告訴編譯器這個變數的值可能會在程式碼外被改變，可能是用於多執行緒環境或是需要與硬體互動的場景
	volatile LONG RecIndex;			// 記錄索引		

	// stack trace origin + unique counts
	// CALL_END的大小等於所有可能的 API 呼叫類型數量
	LONG CallCounts[CALL_END];		// API 呼叫計數
	Origins* CallOrigins[CALL_END];	// API 呼叫來源

	// pointer to last previous mutation
	Mutation* mutStore;			// 最後一次變異的指標

	// doubly linked list
	Execution* prev;
	Execution* next;
};


struct Frame {
	Execution* firstExec = NULL; 	// 指向第一次執行的指標
	Execution* currExec = NULL;		// 指向當前執行的指標
	Mutation* mutHead = NULL;		// 變異列表的頭部
	Mutation* mutCurr = NULL;		// 當前變異
	DWORD dwMutationCount = 0;		// 變異計數

	// list of mutations to avoid due to backtracking
	Mutation* skip = NULL;			// 要跳過的變異

	// callcount sum (avoid recalc)
	LONG act;						// 活動計數
};

struct BackTrackInfo {
	DWORD BackTrackAttempts;		// 回溯嘗試次數
	DWORD BackTrackKept;			// 保留的回溯次數
	LONG InitAct;					// 初始活動
};
