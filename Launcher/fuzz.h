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
// �޲z�C�ӳB�z�{�Ǫ����a�O��
struct LocalRecording {
	// NOTE: this list grows backwards, the last call is the head.(�O���C��O�ϦV�W����(�̫᪺�I�s�b�Y��))
	RecordList* recHead = NULL;		// �O���C���Y��
	RecordList* recCurr = NULL;		// ��e�O��
};

// �l�� API �I�s���ӷ�
struct Origins {
	UINT64 origin;
	Origins* next;
};

// one execution instance
struct Execution {
	LocalRecording recordings[MAX_CHILD];	// ���a��ƩI�s�O���}�C

	// volatile �i�D�sĶ���o���ܼƪ��ȥi��|�b�{���X�~�Q���ܡA�i��O�Ω�h��������ҩάO�ݭn�P�w�餬�ʪ�����
	volatile LONG RecIndex;			// �O������		

	// stack trace origin + unique counts
	// CALL_END���j�p����Ҧ��i�઺ API �I�s�����ƶq
	LONG CallCounts[CALL_END];		// API �I�s�p��
	Origins* CallOrigins[CALL_END];	// API �I�s�ӷ�

	// pointer to last previous mutation
	Mutation* mutStore;			// �̫�@���ܲ�������

	// doubly linked list
	Execution* prev;
	Execution* next;
};


struct Frame {
	Execution* firstExec = NULL; 	// ���V�Ĥ@�����檺����
	Execution* currExec = NULL;		// ���V��e���檺����
	Mutation* mutHead = NULL;		// �ܲ��C���Y��
	Mutation* mutCurr = NULL;		// ��e�ܲ�
	DWORD dwMutationCount = 0;		// �ܲ��p��

	// list of mutations to avoid due to backtracking
	Mutation* skip = NULL;			// �n���L���ܲ�

	// callcount sum (avoid recalc)
	LONG act;						// ���ʭp��
};

struct BackTrackInfo {
	DWORD BackTrackAttempts;		// �^�����զ���
	DWORD BackTrackKept;			// �O�d���^������
	LONG InitAct;					// ��l����
};
