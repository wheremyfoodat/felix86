%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x400",
    "MM7": ["0x8000000000000000", "0x3FFF"]
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

mov rdx, 0xe0000000

mov eax, 0x44800000 ; 1024.0
mov [rdx + 8 * 0], eax
mov eax, -1
mov [rdx + 8 * 1], eax

fld dword [rdx + 8 * 0]

fistp word [rdx + 8 * 1]

fld1

mov eax, 0
mov ax, word [rdx + 8 * 1]

hlt
