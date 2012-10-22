#include <windows.h>
#include <stdio.h>

#define N_THREAD 4

DWORD WINAPI thr(LPVOID lpParam){
	printf("I'm the thread\n");
}

int main(int argc, char *argv[]){
	int i;
	HANDLE thrs[N_THREAD];
	printf("Thread test case\n");
	for(i=0; i < N_THREAD; ++i){
		thrs[i] = CreateThread( NULL, 0, thr, NULL, 0, NULL);
		if(thrs[i] == NULL) ExitProcess(1);
	}
	WaitForMultipleObjects( N_THREAD, thrs, TRUE, INFINITE);
	printf("Thread test finish\n");

	for(i=0; i < N_THREAD; ++i){
		CloseHandle(thrs[i]);
	}
	return 0;
}
