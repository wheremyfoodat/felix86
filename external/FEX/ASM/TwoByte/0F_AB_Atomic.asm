%ifdef CONFIG
{
  "RegData": {
    "R15": "0x1F"
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
mov [rdx + 8 * 2], rax
mov rax, 0x01
mov [rdx + 8 * 3], eax
mov rax, 0x0
mov [rdx + 8 * 3 + 4], eax

xor r15, r15 ; Will contain our results

; Test and set
mov r13, 1
lock bts word [rdx], r13w
cfmerge

; Ensure it is set
mov r13, 1
bt word [rdx], r13w
cfmerge

mov r13, 32
lock bts dword [rdx], r13d
cfmerge

bt dword [rdx], r13d
cfmerge

mov r13, 64 * 3
lock bts qword [rdx], r13
cfmerge

mov r13, 64 * 3
bt qword [rdx], r13
cfmerge

hlt
