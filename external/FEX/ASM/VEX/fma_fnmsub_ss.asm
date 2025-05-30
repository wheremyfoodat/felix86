%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM0": ["0x4040000040e00000", "0x40a0000040800000", "0", "0"],
    "XMM1": ["0xc0e0000042220000", "0xc1100000c1000000", "0", "0"],
    "XMM2": ["0x40600000c24c0000", "0xc0f66666c0b00000", "0", "0"]
  }
}
%endif
bits 64

vmovups ymm0, [rel .data]
vmovups ymm1, [rel .data2]
vmovups ymm2, [rel .data3]

vfnmsub231ss xmm0, xmm1, xmm2
vfnmsub213ss xmm1, xmm0, xmm2
vfnmsub132ss xmm2, xmm1, xmm0

hlt

align 32
.data:
dd 2.0, 3.0, 4.0, 5.0
dd 6.0, 7.0, 8.0, 9.0

.data2:
dd -6.0, -7.0, -8.0, -9.0
dd 20.0, 30.0, 40.0, 50.0

.data3:
dd 1.5, 3.5, -5.5, -7.7
dd -15.5, -21.5, 23.5, 30.1
