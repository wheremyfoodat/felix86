%ifdef CONFIG
{
  "RegData": {
    "XMM0":  ["0x8000000000000000", "0x3FFE"],
    "XMM1":  ["0x8000000000000000", "0xBFFE"]
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

mov rdx, 0xe0000000

mov rax, 0x3ff0000000000000 ; 1.0
mov [rdx + 8 * 0], rax
mov eax, 2
mov [rdx + 8 * 1], eax

fld qword [rdx + 8 * 0]
fidiv dword [rdx + 8 * 1]

fstp tword [rel data]
movups xmm0, [rel data]

; Test negative
mov rax, 0x3ff0000000000000 ; 1.0
mov [rdx + 8 * 0], rax
mov eax, -2
mov [rdx + 8 * 1], eax

fld qword [rdx + 8 * 0]
fidiv dword [rdx + 8 * 1]

fstp tword [rel data]
movups xmm1, [rel data]

hlt

data:
dq 0
dq 0
