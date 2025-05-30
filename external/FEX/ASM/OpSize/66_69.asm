%ifdef CONFIG
{
  "RegData": {
    "XMM0": ["0x7576555677785758", "0x7172515273745354"],
    "XMM1": ["0x7576555677785758", "0x7172515273745354"],
    "XMM2": ["0x6162636465666768", "0x7172737475767778"]
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
punpckhwd xmm0, [rdx + 8 * 2]

movapd xmm1, [rdx]
movapd xmm2, [rdx + 8 * 2]
punpckhwd xmm1, xmm2

hlt
