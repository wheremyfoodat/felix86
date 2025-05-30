%ifdef CONFIG
{
  "RegData": {
    "XMM0": ["0x4142434445464748", "0x5152535455565758"],
    "XMM1": ["0x6162636465666768", "0x7172737475767778"],
    "XMM2": ["0x4546474845464748", "0x4546474845464748"],
    "XMM3": ["0x5152535451525354", "0x5152535451525354"]
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
mov rax, 0x7172737475767778
mov [rdx + 8 * 3], rax

movapd xmm0, [rdx]
movapd xmm1, [rdx + 8 * 2]
pshufd xmm2, xmm0, 0x0
pshufd xmm3, xmm0, 0xFF

hlt
