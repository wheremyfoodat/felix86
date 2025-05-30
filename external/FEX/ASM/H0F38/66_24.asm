%ifdef CONFIG
{
  "RegData": {
    "XMM0": ["0xffffffffffff8788", "0xffffffffffff8586"]
  }
}
%endif
bits 64

mov rdx, 0xe0000000

mov rax, 0x4142434485868788
mov [rdx + 8 * 0], rax
mov rax, 0x5152535455565758
mov [rdx + 8 * 1], rax

mov rax, 0x6162636465666768
mov [rdx + 8 * 2], rax
mov rax, 0x7172737475767778
mov [rdx + 8 * 3], rax

; Fill register with trash
movapd xmm0, [rdx + 8 * 2]

; Now do the move
pmovsxwq xmm0, [rdx + 8 * 0]

hlt
