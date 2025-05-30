%ifdef CONFIG
{
  "RegData": {
    "RBX": "0x09",
    "RCX": "0x9919",
    "RDX": "0x9A999929",
    "RBP": "0x9E9D9C9B9A999939",
    "RDI": "0x81",
    "RSP": "0x7F81",
    "R8":  "0x7F7F7F81",
    "R9":  "0x02",
    "R10": "0x4142427344754777",
    "R11": "0x5152535455565687",
    "R12": "0x6162636465666768"
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

mov rax, 0xD1
sub byte  [r15 + 8 * 0 + 0], al
sub word  [r15 + 8 * 0 + 2], ax
sub dword [r15 + 8 * 0 + 4], eax
sub qword [r15 + 8 * 1 + 0], rax

mov rbx, 0x71
mov rcx, 0x81
mov rdx, 0x91
mov rbp, 0xA1

sub bl,  byte  [r15 + 8 * 2]
sub cx,  word  [r15 + 8 * 2]
sub edx, dword [r15 + 8 * 2]
sub rbp, qword [r15 + 8 * 2]

mov rax, 0x01
sub al, 0x80
mov rdi, rax

mov rax, 0x01
sub ax, 0x8080
mov rsp, rax

mov rax, 0x01
sub eax, 0x80808080
mov r8, rax

mov rax, 0x01
sub rax, -1
mov r9, rax

mov r10, [r15 + 8 * 0]
mov r11, [r15 + 8 * 1]
mov r12, [r15 + 8 * 2]

hlt
