%ifdef CONFIG
{
  "RegData": {
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  },
  "HostFeatures": ["3DNOW"]
}
%endif
bits 64

femms ; Just ensure it runs

hlt
