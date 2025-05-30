%ifdef CONFIG
{
  "RegData": {
    "MM6":  ["0xE666666666666668", "0xBFFE"],
    "MM7":  ["0xC000000000000000", "0x4000"]
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

lea rdx, [rel data]
fld tword [rdx + 8 * 0]

lea rdx, [rel data2]
fld tword [rdx + 8 * 0]

fprem1

hlt

align 8
data:
  dt 3.0
  dq 0
data2:
  dt 5.1
  dq 0
