#pragma once

#include <cstdint>
#include <vector>
#include <unordered_map>

#include "xxhash32.h"
#include "prng.h"

typedef std::vector<std::pair<std::string, std::vector<uint32_t>>> ImportHashTable;


#define e(STRING) make_encrypted_string(STRING)
#define h(STRING) xxh32_consteval(STRING, 0)

static const ImportHashTable imports = {
	{ e("KERNEL32.DLL"), { h("GetProcAddress"), h("GetModuleHandleA"), h("LoadLibraryA"), h("CreateProcessA"), h("CreateProcessW"), h("IsDebuggerPresent")}},
	{ e("user32.dll"), {h("MessageBoxA")}},
	{ e("ws2_32.dll"), { h("htons"), h("ntohs"), h("inet_addr"), h("WSAStartup"), h("WSASocketA"), h("WSASocketW"), h("WSAConnect") }},


};