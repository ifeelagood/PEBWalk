#pragma once

#include <Windows.h>
#include <winternl.h>

#include <string>
#include <vector>
#include <cstring>
#include <map>
#include <set>
#include <type_traits>
#include <utility>
#include <unordered_map>

#include "xxhash32.h"
#include "prng.h"

#define e(STRING) make_encrypted_string(STRING)


extern "C" void* GetPEBAddress32();
extern "C" void* GetPEBAddress64();


// get address to PEB
static inline PEB* GetPEB() {
#if defined(_M_IX86)
    return (PEB*)GetPEBAddress32();
#else 
    return (PEB*)GetPEBAddress64();
#endif
}

class Loader {
private:
    PEB* peb;

private:
    // function pointers and types to be loaded by walking PEB
    typedef FARPROC(WINAPI* t_GetProcAddress)(HMODULE, LPCSTR);
    typedef HMODULE(WINAPI* t_LoadLibraryA)(LPCSTR);
    typedef HMODULE(WINAPI* t_GetModuleHandleA)(LPCSTR);

    t_GetProcAddress GetProcAddress = nullptr;
    t_LoadLibraryA LoadLibraryA = nullptr;
    t_GetModuleHandleA GetModuleHandleA = nullptr;

private:
    // replicas of GetModuleHandle and GetProcAddress
    HMODULE GetModuleHandlePEB(const char* module_name);
    PVOID GetProcAddressPEB(HMODULE module, LPCSTR proc_name);

private:
    PVOID FindFunctionByHash(HMODULE module, uint32_t func_hash);

private:    
    // function name hash -> function pointer
    std::unordered_map<uint32_t, PVOID> functions;

    std::vector<HMODULE> module_handles;

public:
    Loader(std::vector<std::string> _modules);

    // delete copy constructors
    Loader(const Loader&) = delete; 
    Loader& operator=(const Loader&) = delete;

    static Loader& get_instance() {
        static Loader instance({ e("KERNEL32.dll"), e("user32.dll"), e("ws2_32.dll") });
        return instance;
    }

public:
    PVOID LookupFunction(uint32_t func);

public:
    template <typename Fn, typename... Args>
    auto call(uint32_t hash, Args... args) {
        return reinterpret_cast<Fn>(LookupFunction(hash))(args...);
    }


};