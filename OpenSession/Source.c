/*
WTSEnumerateProcessesA
*/
#include <stdio.h>
#include <Windows.h>
#include <WtsApi32.h>

//#pragma comment(lib, "cmcfg32.lib")
#pragma comment(lib, "Wtsapi32.lib")

//#define SE_TCB_NAME TEXT("SeTcbPrivilege")

// function to sell privilege
BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

// main function that would go in onstart() in the service
int main() {
    // token we use
//    HANDLE hToken = INVALID_HANDLE_VALUE;
    HANDLE hToken;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("bleep\n");
        return FALSE;
    }

	// get the console ID
	DWORD console_id;
	console_id = WTSGetActiveConsoleSessionId();
	printf("console id is: %d\n", console_id);

	// set the privilege to query user token
    SetPrivilege(hToken, SE_TCB_NAME, 1); // true to enable this privilege on the token 

    // query for user token
	BOOL queryres;
	queryres = WTSQueryUserToken(console_id, &hToken);
	printf("res: %d\n", queryres);

	// index of the session
//	if (WTSQueryUserToken(pI[i].SessionId, &hToken)) {
//		printf("test\n");
//	}


	//}




	return 0;
}