%ifdef CONFIG
{
  "RegData": {
    "RAX": "0xF1F2F3F4F5F6F7F8",
    "RDX": "0xF1F2F3F4F5F6F7F8",
    "RSI": "0x0",
    "RDI": "0xE0000020"
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
mov rax, 0x0
mov [rdx + 8 * 2], rax
mov [rdx + 8 * 3], rax
mov [rdx + 8 * 4], rax

lea rdi, [rdx + 8 * 2]

cld
mov rax, 0xF1F2F3F4F5F6F7F8
mov rcx, 2
repne stosq ; rdi <- rax

mov rax, [rdx + 8 * 2]
mov rsi, [rdx + 8 * 4]
mov rdx, [rdx + 8 * 3]
hlt
