%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM0":  ["0x2179B0697D5378C4", "0x3B8E6EAE8C165248", "0x0000000000000000", "0x0000000000000000"],
    "XMM1":  ["0x1ED68638699D35CA", "0x5E2E7560AB7B5262", "0x0000000000000000", "0x0000000000000000"],
    "XMM2":  ["0x165C42291F28194C", "0x0923643C32130145", "0x0000000000000000", "0x0000000000000000"],
    "XMM3":  ["0x2179B0697D5378C4", "0x3B8E6EAE8C165248", "0x0000000000000000", "0x0000000000000000"],
    "XMM4":  ["0x1ED68638699D35CA", "0x5E2E7560AB7B5262", "0x0000000000000000", "0x0000000000000000"],
    "XMM5":  ["0x165C42291F28194C", "0x0923643C32130145", "0x0000000000000000", "0x0000000000000000"],
    "XMM10": ["0x2179B0697D5378C4", "0x3B8E6EAE8C165248", "0x2179B0697D5378C4", "0x3B8E6EAE8C165248"],
    "XMM11": ["0x1ED68638699D35CA", "0x5E2E7560AB7B5262", "0x1ED68638699D35CA", "0x5E2E7560AB7B5262"],
    "XMM12": ["0x165C42291F28194C", "0x0923643C32130145", "0x165C42291F28194C", "0x0923643C32130145"],
    "XMM13": ["0x2179B0697D5378C4", "0x3B8E6EAE8C165248", "0x2179B0697D5378C4", "0x3B8E6EAE8C165248"],
    "XMM14": ["0x1ED68638699D35CA", "0x5E2E7560AB7B5262", "0x1ED68638699D35CA", "0x5E2E7560AB7B5262"],
    "XMM15": ["0x165C42291F28194C", "0x0923643C32130145", "0x165C42291F28194C", "0x0923643C32130145"]
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

lea rdx, [rel .data]

vmovapd ymm6, [rdx + 32 * 1]
vmovapd ymm7, [rdx + 32 * 2]
vmovapd ymm8, [rdx + 32 * 3]
vmovapd ymm9, [rdx]

; 128-bit register only
vpavgb xmm0, xmm9, xmm6
vpavgb xmm1, xmm9, xmm7
vpavgb xmm2, xmm9, xmm8

; 128-bit memory operand
vpavgb xmm3, xmm9, [rdx + 32 * 1]
vpavgb xmm4, xmm9, [rdx + 32 * 2]
vpavgb xmm5, xmm9, [rdx + 32 * 3]

; 256-bit register only
vpavgb ymm10, ymm9, ymm6
vpavgb ymm11, ymm9, ymm7
vpavgb ymm12, ymm9, ymm8

; 256-bit memory operand
vpavgb ymm13, ymm9, [rdx + 32 * 1]
vpavgb ymm14, ymm9, [rdx + 32 * 2]
vpavgb ymm15, ymm9, [rdx + 32 * 3]

hlt

align 32
.data:
dq 0x2BB883523D4F3197
dq 0x1246C77764260189
dq 0x2BB883523D4F3197
dq 0x1246C77764260189

dq 0x163ADD80BC57BEF1
dq 0x64D615E5B405A306
dq 0x163ADD80BC57BEF1
dq 0x64D615E5B405A306

dq 0x11F4881D94EB39FC
dq 0xA9162248F2D0A23A
dq 0x11F4881D94EB39FC
dq 0xA9162248F2D0A23A

dq 0x0000000000000000
dq 0x0000000000000000
dq 0x0000000000000000
dq 0x0000000000000000
