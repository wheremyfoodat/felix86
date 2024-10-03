%ifdef CONFIG
{
  "RegData": {
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

emms ; Just ensure it runs

hlt
