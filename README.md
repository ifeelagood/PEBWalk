# PEB Walk

The code is a proof-of-concept of the age old method of import table obsfusaction by loading functions dynamically using the windows API, specifically LoadLibraryA, GetProcAddress and GetModuleHandle. 

This goes a step further, by choosing to NOT import these functions by linking, but by determining the location of functions by querying the Process Envrionment Block. The PEB is always at gs:[0x60] on 64 bit systems. The code which "walks" the peb is essentially a reimplementation of GetProcAddress and GetModuleHandle. 

All the code does is open a reverse shell on a specified host and port.

# Additional obsfuscation and encrytion

- strings are encrypted at compile time and decrypted during runtime with an XOR cipher seeded with a linear congruential prng.

- xxhash32 algorithm is implemented with methods which guarantee compile time evalulation (C++20 consteval).

- imports are hashed and looked up using a hashmap for even further obsfuscation.

# Undefined behaviour

There are some evil methods in this code, not because they are malicious per se but because they are undefined behaviour. Essentially, C++ cannot call a function of a void* type, but it can be cast to the correct signature by providing the return type, function parameters and calling convention (order by which variables are stored in registers). I tried using template arguments so i didn't have to write lots of obtuse boilerplate:

```
    template <typename Ret, typename... Args>
    Ret call_stdcall(uint32_t hash, Args... args) {
        return reinterpret_cast<Ret(__stdcall*)(Args...)>(functions[hash])(args...);
    }


//Usage:
	ldr.call_stdcall<int, HWND, LPCSTR, LPCSTR, UINT>(g("MessageBoxA"), NULL, "PEB walk success", "Success", MB_OK);
	
```

I don't think this should be done in any circumstances whatsoever
