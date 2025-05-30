%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x4142436245654748",
    "RBX": "0x5152535455565795",
    "RCX": "0x61626364656667A5"
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

mov rdx, 0xe0000000

mov rax, 0x4142434445464748
mov [rdx + 8 * 0], rax
mov rax, 0x5152535455565758
mov [rdx + 8 * 1], rax
mov rax, 0x6162636465666768
mov [rdx + 8 * 2], rax

clc
lock sbb word [rdx + 8 * 0 + 2], -31
clc
lock sbb dword [rdx + 8 * 1 + 0], -31
clc
lock sbb qword [rdx + 8 * 2 + 0], -31

stc
lock sbb word [rdx + 8 * 0 + 4], -31
stc
lock sbb dword [rdx + 8 * 1 + 0], -31
stc
lock sbb qword [rdx + 8 * 2 + 0], -31

mov rax, [rdx + 8 * 0]
mov rbx, [rdx + 8 * 1]
mov rcx, [rdx + 8 * 2]

hlt
