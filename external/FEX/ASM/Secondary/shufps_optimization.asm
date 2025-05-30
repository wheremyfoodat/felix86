%ifdef CONFIG
{
  "RegData": {
    "XMM0":  ["0x4054c664c2f837b5", "0x4044836d86ec17ec"],
    "XMM1":  ["0x402a1e1c58255b03", "0x4035fe425aee6320"],
    "XMM2":  ["0x401568e0c9d9d346", "0x40154b7d41743e96"],
    "XMM3":  ["0x40154b7d41743e96", "0x403d075a31a4bdba"],
    "XMM4":  ["0xbd66277c31a4bdba", "0x4ea4a8c17ebaf102"],
    "XMM5":  ["0x4056d74040334ec1", "0x40497b13404439b5"],
    "XMM6":  ["0x404439b5404439b5", "0x4037f9ca18bd6627"],
    "XMM7":  ["0x4037f9ca4037f9ca", "0x403839b866e43aa8"],
    "XMM8":  ["0x403839b8403839b8", "0x4058bc1f212d7732"],
    "XMM9":  ["0x4058bc1f212d7732", "0xa10e0221a10e0221"],
    "XMM10": ["0x4058defb00bcbe62", "0x9eecbfb19eecbfb1"],
    "XMM11": ["0x40503e3c4052997f", "0x40395a6bf8769ec3"],
    "XMM12": ["0x40419d2240395a6b", "0x40177e28240b7803"],
    "XMM13": ["0x240b780340177e28", "0x404a03c74fb549f9"],
    "XMM14": ["0x9f16b11c40408402", "0x404d31595feda661"],
    "XMM15": ["0x5feda6615feda661", "0x7aa25d8d7aa25d8d"]
  }
}
%endif
bits 64

movaps xmm0, [rel .data + 16 * 0]
movaps xmm1, [rel .data + 16 * 1]

movaps xmm2, [rel .data + 16 * 2]
movaps xmm3, [rel .data + 16 * 3]

movaps xmm4, [rel .data + 16 * 4]
movaps xmm5, [rel .data + 16 * 5]

movaps xmm6, [rel .data + 16 * 6]
movaps xmm7, [rel .data + 16 * 7]

movaps xmm8, [rel .data + 16 * 8]
movaps xmm9, [rel .data + 16 * 9]

movaps xmm10, [rel .data + 16 * 10]
movaps xmm11, [rel .data + 16 * 11]

movaps xmm12, [rel .data + 16 * 12]
movaps xmm13, [rel .data + 16 * 13]

movaps xmm14, [rel .data + 16 * 14]
movaps xmm15, [rel .data + 16 * 15]

shufps xmm0, xmm1, 01000100b
shufps xmm1, xmm2, 11101110b
shufps xmm2, xmm3, 11100100b
shufps xmm3, xmm4, 01001110b
shufps xmm4, xmm5, 10001000b
shufps xmm5, xmm6, 11011101b
shufps xmm6, xmm7, 11100101b
shufps xmm7, xmm8, 11101111b
shufps xmm8, xmm9, 01001111b
shufps xmm9, xmm10, 00000100b
shufps xmm10, xmm11, 00001110b
shufps xmm11, xmm12, 11100111b
shufps xmm12, xmm13, 01000111b
shufps xmm13, xmm14, 11100001b
shufps xmm14, xmm15, 01000001b
shufps xmm15, [rel .data + 16 * 16], 0

hlt

align 16
; 512bytes of random data
.data:
dq 83.0999,69.50512,41.02678,13.05881,5.35242,21.9932,9.67383,5.32372,29.02872,66.50151,19.30764,91.3633,40.45086,50.96153,32.64489,23.97574,90.64316,24.22547,98.9394,91.21715,90.80143,99.48407,64.97245,74.39838,35.22761,25.35321,5.8732,90.19956,33.03133,52.02952,58.38554,10.17531,47.84703,84.04831,90.02965,65.81329,96.27991,6.64479,25.58971,95.00694,88.1929,37.16964,49.52602,10.27223,77.70605,20.21439,9.8056,41.29389,15.4071,57.54286,9.61117,55.54302,52.90745,4.88086,72.52882,3.0201,56.55091,71.22749,61.84736,88.74295,47.72641,24.17404,33.70564,96.71303
