%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x1",
    "RBX": "0xFFFFFFFFFFFFFFFF"
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

mov r15, 0xe0000000

mov rax, 0x0
mov [r15 + 8 * 0], rax
mov rax, 0x1
mov [r15 + 8 * 1], rax
mov rax, 0x2
mov [r15 + 8 * 2], rax

mov r10, 0x2
mov r11, 0x0
mov r12, 0x1

cmp r10d, r12d

mov rax, -1
mov rbx, -1
cmovnc rax, [r15 + 8 * 1]
cmovc  rbx, [r15 + 8 * 0]

hlt
