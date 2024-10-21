.code
    PUBLIC GetPEBAddress32
    PUBLIC GetPEBAddress64

GetPEBAddress32 PROC
    mov eax, dword ptr fs:[30h]
    ret
GetPEBAddress32 ENDP

GetPEBAddress64 PROC
    mov rax, qword ptr gs:[60h]
    ret
GetPEBAddress64 ENDP
END