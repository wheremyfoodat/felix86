%ifdef CONFIG
{
  "RegData": {
    "R15": "0x3"
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

%macro cfmerge 0

; Get CF
sbb r14, r14
and r14, 1

; Merge in to results
shl r15, 1
or r15, r14

%endmacro

mov rdx, 0xe0000000

mov rax, 0xFFFFFFFF80000000
mov [rdx + 8 * 0], rax
mov [rdx + 8 * 1], rax
mov rax, 0x0
mov [rdx + 8 * 2], rax
mov rax, 0x01
mov [rdx + 8 * 3], eax
mov rax, 0x0
mov [rdx + 8 * 3 + 4], eax

xor r15, r15 ; Will contain our results

db 0xF2 ; Prefix with F2. Shouldn't change behaviour
bt word [rdx], 1
cfmerge

mov r13, 32
db 0xF2 ; Prefix with F2. Shouldn't change behaviour
bt dword [rdx], r13d
cfmerge

db 0xF2 ; Prefix with F2. Shouldn't change behaviour
bt qword [rdx], 64 * 2 + 63
cfmerge

hlt


