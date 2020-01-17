/*
WTSEnumerateProcessesA
*/
#include <stdio.h>
#include <Windows.h>
#include <WtsApi32.h>

#pragma comment(lib, "Wtsapi32.lib");

int main() {
	PWTS_SESSION_INFOA pI;
	DWORD pCount;
	WTSEnumerateSessionsA(
		WTS_CURRENT_SERVER_HANDLE,
		0,
		1,
		&pI,
		&pCount
	);
	for (unsigned int i = 0; i < pCount; i++) {
		printf("ID: %s\n", pI[i].pWinStationName);
	}
	return 0;
}