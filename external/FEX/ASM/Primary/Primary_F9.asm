%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x1"
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

stc

; Get CF
sbb rax, rax
and rax, 1

hlt
