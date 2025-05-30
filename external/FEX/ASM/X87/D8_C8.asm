%ifdef CONFIG
{
  "RegData": {
    "MM7":  ["0x8000000000000000", "0x4001"]
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

mov rdx, 0xe0000000

mov rax, 0x4000000000000000 ; 2.0
mov [rdx + 8 * 0], rax

fld qword [rdx + 8 * 0]
fmul st0, st0
hlt
