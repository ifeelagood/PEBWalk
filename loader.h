#pragma once

#include <Windows.h>
#include <winternl.h>

#include <vector>
#include <cstring>
#include <map>
#include <set>

#include "xxhash32.h"
#include "imports.h"

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
    void ResolveFunctionHashes(HMODULE module);

private:
    std::set<uint32_t> unresolved_hashes;

    // module name hash -> module base address
    std::unordered_map<uint32_t, HMODULE> module_handles;
    
    // function name hash -> function pointer
    std::unordered_map<uint32_t, PVOID> functions;



public:
    Loader(const ImportHashTable& imports);

public:
    PVOID LookupFunction(uint32_t func);

public:
    template <typename Ret, typename... Args> 
    Ret call_stdcall(PVOID func, Args... args) {
        return reinterpret_cast<Ret(__stdcall*)(Args...)>(func)(args...);
    }

    template <typename Ret, typename... Args>
    Ret call_stdcall(uint32_t hash, Args... args) {
        return reinterpret_cast<Ret(__stdcall*)(Args...)>(functions[hash])(args...);
    }

    template <typename Ret, typename... Args>
    Ret call_cdecl(PVOID func, Args... args) {
        return reinterpret_cast<Ret(__cdecl*)(Args...)>(func)(args...);
    }

    template <typename Ret, typename... Args>
    Ret call_cdecl(uint32_t hash, Args... args) {
        return reinterpret_cast<Ret(__cdecl*)(Args...)>(functions[hash])(args...);
    }
};

