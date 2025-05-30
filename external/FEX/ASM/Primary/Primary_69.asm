%ifdef CONFIG
{
  "RegData": {
    "RAX": "0xB800",
    "RBX": "0xA9A8A800",
    "RSI": "0x9D9C9B9A99989800"
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

mov r15, 0xe0000000

mov rax, 0x4142434445464748
mov [r15 + 8 * 0], rax
mov rax, 0x5152535455565758
mov [r15 + 8 * 1], rax
mov rax, 0x6162636465666768
mov [r15 + 8 * 2], rax

mov rax, 0x0
mov [r15 + 8 * 3], rax
mov [r15 + 8 * 4], rax

imul ax, word [r15 + 8 * 0 + 0], -256
mov word [r15 + 8 * 3 + 0], ax

imul eax, dword [r15 + 8 * 1 + 0], -256
mov dword [r15 + 8 * 4 + 0], eax

imul rax, qword [r15 + 8 * 2 + 0], -256
mov rsi, rax

mov rax, [r15 + 8 * 3]
mov rbx, [r15 + 8 * 4]

hlt
