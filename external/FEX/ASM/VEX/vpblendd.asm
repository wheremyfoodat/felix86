%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM2": ["0xAAAAAAAABBBBBBBB", "0xCCCCCCCCDDDDDDDD", "0xEEEEEEEEFFFFFFFF", "0x9999999988888888"],
    "XMM3": ["0x1111111122222222", "0x3333333344444444", "0x5555555566666666", "0x7777777788888888"],
    "XMM4": ["0xAAAAAAAABBBBBBBB", "0xCCCCCCCCDDDDDDDD", "0x0000000000000000", "0x0000000000000000"],
    "XMM5": ["0x1111111122222222", "0x3333333344444444", "0x0000000000000000", "0x0000000000000000"],
    "XMM6": ["0x11111111BBBBBBBB", "0x33333333DDDDDDDD", "0x55555555FFFFFFFF", "0x7777777788888888"],
    "XMM7": ["0xAAAAAAAA22222222", "0xCCCCCCCC44444444", "0xEEEEEEEE66666666", "0x9999999988888888"],
    "XMM8": ["0x11111111BBBBBBBB", "0x33333333DDDDDDDD", "0x0000000000000000", "0x0000000000000000"],
    "XMM9": ["0xAAAAAAAA22222222", "0xCCCCCCCC44444444", "0x0000000000000000", "0x0000000000000000"]
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

lea rdx, [rel .data]

vmovapd ymm0, [rdx]
vmovapd ymm1, [rdx + 32]

; Selecting all of one input vector
vpblendd ymm2, ymm0, ymm1, 0    ; All of ymm0
vpblendd ymm3, ymm0, ymm1, 0xFF ; All of ymm1

vpblendd xmm4, xmm0, xmm1, 0    ; All of xmm0
vpblendd xmm5, xmm0, xmm1, 0xFF ; All of xmm1

; Alternating source vectors
vpblendd ymm6, ymm0, ymm1, 0b10101010
vpblendd ymm7, ymm0, ymm1, 0b01010101

vpblendd xmm8, xmm0, xmm1, 0b10101010
vpblendd xmm9, xmm0, xmm1, 0b01010101

hlt

align 32
.data:
dq 0xAAAAAAAABBBBBBBB
dq 0xCCCCCCCCDDDDDDDD
dq 0xEEEEEEEEFFFFFFFF
dq 0x9999999988888888

dq 0x1111111122222222
dq 0x3333333344444444
dq 0x5555555566666666
dq 0x7777777788888888
