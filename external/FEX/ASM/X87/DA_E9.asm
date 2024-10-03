%ifdef CONFIG
{
  "RegData": {
    "MM6":  ["0x8000000000000000", "0x3FFF"],
    "MM7":  ["0x8000000000000000", "0x3FFF"]
  }
}
%endif
bits 64

; Only tests pop behaviour
fld1
fldz
fldz
fucompp
fld1

hlt
