#include "loader.h"

#include "prng.h"

#include <stdexcept>
#include <string.h>

typedef uint64_t QWORD;

#define e(STRING) make_encrypted_string(STRING)

#define a(STR) xxh32_consteval(STR, 0)


Loader::Loader(const ImportHashTable& imports)
    : peb(GetPEB())
{
    // 1. resolve kernel 32
    HMODULE kernel32base = GetModuleHandlePEB(e("KERNEL32.DLL").c_str());

    // TODO are exceptions easy to reverse?
    if (!kernel32base) {
        throw std::runtime_error("Could not resolve kernel32.dll base address");
        return;
    }

    // 2. resolve required functions
    functions[a("GetProcAddress")]   = GetProcAddressPEB(kernel32base, e("GetProcAddress").c_str());
    functions[a("GetModuleHandleA")] = GetProcAddressPEB(kernel32base, e("GetModuleHandleA").c_str());
    functions[a("LoadLibraryA")]     = GetProcAddressPEB(kernel32base, e("LoadLibraryA").c_str());


    this->GetModuleHandleA  = (t_GetModuleHandleA)  functions[a("GetModuleHandleA")];
    this->LoadLibraryA      = (t_LoadLibraryA)      functions[a("LoadLibraryA")];
    this->GetProcAddress    = (t_GetProcAddress)    functions[a("GetProcAddress")];

    // 3. load libraries from import
    for (auto mod : imports) {
        HMODULE handle;
        if (mod.first == e("KERNEL32.DLL")) {
            handle = kernel32base;
        }
        else {
            handle = this->LoadLibraryA(mod.first.c_str());
        }

        if (!handle) {
            throw std::runtime_error("could not load library");
            return;
        }
        module_handles[xxh32_runtime(mod.first.c_str())] = handle;

        for (auto func_hash : mod.second) {
            unresolved_hashes.insert(func_hash);
        }

        // walk peb
        ResolveFunctionHashes(handle);

        if (!unresolved_hashes.empty()) {
            throw std::runtime_error("unresolved hashes");
        }
    }

}

PVOID Loader::LookupFunction(uint32_t func)
{
    if (functions[func]) {
        return functions[func];
    }
    return nullptr;
}

HMODULE Loader::GetModuleHandlePEB(const char* module_name) {
    PLDR_DATA_TABLE_ENTRY module_ldr_entry;

    LIST_ENTRY* list_entry = peb->Ldr->InMemoryOrderModuleList.Flink;
    do {
        module_ldr_entry = CONTAINING_RECORD(list_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // convert full path to cstring
        char full_dll_name[256];
        size_t i;
        for (i = 0; i < module_ldr_entry->FullDllName.Length / sizeof(wchar_t) && i < sizeof(full_dll_name) - 1; i++) {
            full_dll_name[i] = (char)module_ldr_entry->FullDllName.Buffer[i];
        }
        full_dll_name[i] = '\0';

        // get lower path
        char* base_dll_name = strrchr(full_dll_name, '\\');
        base_dll_name = (base_dll_name == nullptr) ? full_dll_name : base_dll_name+1;

        if (strcmp(base_dll_name, module_name) == 0) {
            return (HMODULE)module_ldr_entry->DllBase;
        }

        list_entry = list_entry->Flink;
    } while (list_entry != &peb->Ldr->InMemoryOrderModuleList);

    return nullptr;
}

PVOID Loader::GetProcAddressPEB(HMODULE hModule, LPCSTR lpProcName)
{
    // TODO 32 bit support
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS32 pNTHeaders32 = (PIMAGE_NT_HEADERS32)((BYTE*)hModule + pDOSHeader->e_lfanew);
    PIMAGE_NT_HEADERS64 pNTHeaders64 = (PIMAGE_NT_HEADERS64)((BYTE*)hModule + pDOSHeader->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY pExportDirectory = nullptr;
    
    if (pNTHeaders32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNTHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    else if (pNTHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + pNTHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    else {
        return nullptr;
    }
    // TODO exception

    DWORD* pAddressOfFunctions      = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames          = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals    = (WORD*)((BYTE*)hModule + pExportDirectory->AddressOfNameOrdinals);

    for (QWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);
        if (strcmp(functionName, lpProcName) == 0) {
            return (PVOID)((BYTE*)hModule + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
    }
    return NULL;
}

void Loader::ResolveFunctionHashes(HMODULE hModule)
{
    // TODO 32 bit support
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS32 pNTHeaders32 = (PIMAGE_NT_HEADERS32)((BYTE*)hModule + pDOSHeader->e_lfanew);
    PIMAGE_NT_HEADERS64 pNTHeaders64 = (PIMAGE_NT_HEADERS64)((BYTE*)hModule + pDOSHeader->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY pExportDirectory = nullptr;

    if (pNTHeaders32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNTHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    else if (pNTHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + pNTHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    else {
        throw std::runtime_error("bad magic");
    }

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDirectory->AddressOfNameOrdinals);

    for (QWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);

        uint32_t key = xxh32_runtime(functionName, 0);

        if (unresolved_hashes.count(key)) {
            auto func = (PVOID)((BYTE*)hModule + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            
            functions[key] = func;

            unresolved_hashes.erase(key);
        }
    }

    return;
}


