%ifdef CONFIG
{
  "RegData": {
    "XMM0": ["0x4142434445464748", "0x5152535455565758"],
    "XMM1": ["0x0000000045464748", "0x0"]
  },
  "HostFeatures": ["SSE4A"]
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

movaps xmm0, [rdx + 8 * 0]
movntss [rdx + 8 * 2], xmm0
movaps xmm1, [rdx + 8 * 2]

hlt
