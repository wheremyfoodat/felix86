%ifdef CONFIG
{
  "RegData": {
    "XMM1":  ["0", "0", "0", "0"],
    "XMM3":  ["0xcb60805f6799bee3", "0x6778ae2a2522e0af", "0xead2e747388e768d", "0x88bd62c1a2ff64bc"],
    "XMM4":  ["0xe273f1177f80d2ec", "0xd7e273f1177f80d2", "0xa9d7e273f1177f80", "0x35a9d7e273f1177f"],
    "XMM5":  ["0x341ce2bf6334292d", "0x1ce2bf6334292db6", "0xe2bf6334292db6b8", "0xbf6334292db6b85f"],
    "XMM6":  ["0x2db6b85f6135a9d7", "0x2db6b85f6135a9d7", "0x2db6b85f6135a9d7", "0x2db6b85f6135a9d7"],
    "XMM7":  ["0xe273f1177f80d2ec", "0x0f350767409162b7", "0x002fd22652633359", "0xc0a14faff7b7368a"],
    "XMM8":  ["0x341ce2bf6334292d", "0x0f350767409162b7", "0x002fd22652633359", "0xc0a14faff7b7368a"],
    "XMM9":  ["0x2db6b85f6135a9d7", "0x0f350767409162b7", "0x002fd22652633359", "0xc0a14faff7b7368a"],
    "XMM10": ["0xf1cda2562209301d", "0x0f350767409162b7", "0x002fd22652633359", "0x35a9d7e273f1177f"],
    "XMM11": ["0xf1cda2562209301d", "0x0f350767409162b7", "0x002fd22652633359", "0xbf6334292db6b85f"],
    "XMM12": ["0xf1cda2562209301d", "0x0f350767409162b7", "0x002fd22652633359", "0x2db6b85f6135a9d7"],
    "XMM13": ["0xf1cda2562209301d", "0x0f350767409162b7", "0x002fd22652633359", "0xc0a14faff7b7368a"],
    "XMM14": ["0xf1cda2562209301d", "0x0f350767409162b7", "0x002fd22652633359", "0xc0a14faff7b7368a"],
    "XMM15": ["0xf1cda2562209301d", "0x0f350767409162b7", "0x002fd22652633359", "0xc0a14faff7b7368a"]
  },
  "HostFeatures": ["AVX"]
}
%endif
bits 64

; 256-bit
; 1x displacement
; 32-bit indexes

lea rax, [rel .data_mid]

vmovapd ymm15, [rel .data]
vmovapd ymm14, [rel .data]
vmovapd ymm13, [rel .data]
vmovapd ymm12, [rel .data]
vmovapd ymm11, [rel .data]
vmovapd ymm10, [rel .data]
vmovapd ymm9, [rel .data]
vmovapd ymm8, [rel .data]
vmovapd ymm7, [rel .data]
vmovapd ymm6, [rel .data]
vmovapd ymm5, [rel .data]
vmovapd ymm4, [rel .data]

; Zero mask
vmovaps xmm0, [rel .index_d0]
vmovaps ymm1, [rel .mask_0000]
vpgatherdq ymm15, [xmm0 * 1 + rax], ymm1

vmovaps xmm0, [rel .index_positive_increment]
vmovaps ymm1, [rel .mask_0000]
vpgatherdq ymm14, [xmm0 * 1 + rax], ymm1

vmovaps xmm0, [rel .index_negative_decrement]
vmovaps ymm1, [rel .mask_0000]
vpgatherdq ymm13, [xmm0 * 1 + rax], ymm1

; First element Mask
vmovaps xmm0, [rel .index_d0]
vmovaps ymm1, [rel .mask_0001]
vpgatherdq ymm12, [xmm0 * 1 + rax], ymm1

vmovaps xmm0, [rel .index_positive_increment]
vmovaps ymm1, [rel .mask_0001]
vpgatherdq ymm11, [xmm0 * 1 + rax], ymm1

vmovaps xmm0, [rel .index_negative_decrement]
vmovaps ymm1, [rel .mask_0001]
vpgatherdq ymm10, [xmm0 * 1 + rax], ymm1

; Top element mask
vmovaps xmm0, [rel .index_d0]
vmovaps ymm1, [rel .mask_1000]
vpgatherdq ymm9, [xmm0 * 1 + rax], ymm1

vmovaps xmm0, [rel .index_positive_increment]
vmovaps ymm1, [rel .mask_1000]
vpgatherdq ymm8, [xmm0 * 1 + rax], ymm1

vmovaps xmm0, [rel .index_negative_decrement]
vmovaps ymm1, [rel .mask_1000]
vpgatherdq ymm7, [xmm0 * 1 + rax], ymm1

; Full Mask
vmovaps xmm0, [rel .index_d0]
vmovaps ymm1, [rel .mask_1111]
vpgatherdq ymm6, [xmm0 * 1 + rax], ymm1

vmovaps xmm0, [rel .index_positive_increment]
vmovaps ymm1, [rel .mask_1111]
vpgatherdq ymm5, [xmm0 * 1 + rax], ymm1

vmovaps xmm0, [rel .index_negative_decrement]
vmovaps ymm1, [rel .mask_1111]
vpgatherdq ymm4, [xmm0 * 1 + rax], ymm1

; Full range, full mask
vmovaps xmm0, [rel .index_full_range]
vmovaps ymm1, [rel .mask_1111]
vpgatherdq ymm3, [xmm0 * 1 + rax], ymm1

; ymm1 will be zero after this.

hlt

align 32

; Masks only care about the sign bit.
.mask_0000:
dq 0, 0, 0, 0

.mask_0001:
dq 0, 0, 0, 0x8000_0000_0000_0000

.mask_1000:
dq 0x8000_0000_0000_0000, 0, 0, 0

.mask_1111:
dq 0x8000_0000_0000_0000, 0x8000_0000_0000_0000, 0x8000_0000_0000_0000, 0x8000_0000_0000_0000

; Indexing is a signed 32-bit integer.
.index_d0:
dd 0, 0, 0, 0, 0, 0, 0, 0

.index_positive_increment:
dd 7, 6, 5, 4, 3, 2, 1, 0

.index_negative_decrement:
dd -8, -7, -6, -5, -4, -3, -2, -1

.index_full_range:
dd -992, -512, -256, -128, 128, 256, 512, 992

; Random data, 512-byte per line
.data:
db 0x1d, 0x30, 0x09, 0x22, 0x56, 0xa2, 0xcd, 0xf1, 0xb7, 0x62, 0x91, 0x40, 0x67, 0x07, 0x35, 0x0f, 0x59, 0x33, 0x63, 0x52, 0x26, 0xd2, 0x2f, 0x00, 0x8a, 0x36, 0xb7, 0xf7, 0xaf, 0x4f, 0xa1, 0xc0, 0xe3, 0xbe, 0x99, 0x67, 0x5f, 0x80, 0x60, 0xcb, 0x43, 0xfa, 0x5b, 0x86, 0xb1, 0x11, 0xbc, 0xb3, 0x7b, 0x43, 0x5b, 0x45, 0x9e, 0x33, 0x89, 0xb5, 0x1b, 0xb9, 0x33, 0x4f, 0xdb, 0x5d, 0x93, 0xd6, 0x4f, 0xbc, 0x37, 0xde, 0xeb, 0xdb, 0x43, 0x2b, 0x05, 0x60, 0xb8, 0x98, 0x5c, 0xa3, 0xe3, 0x1b, 0x33, 0x03, 0x29, 0x4b, 0x12, 0x4c, 0x1e, 0xe6, 0x5e, 0x0e, 0x6c, 0xa1, 0xb9, 0x36, 0xfa, 0x6c, 0x7f, 0xc6, 0xa8, 0x38, 0x73, 0x2a, 0x0a, 0x25, 0x69, 0xa5, 0x97, 0x3f, 0x24, 0x00, 0x30, 0x4d, 0x27, 0xb3, 0x94, 0x48, 0xef, 0x47, 0x98, 0x71, 0x0d, 0x56, 0x76, 0xec, 0x41, 0x12, 0x9b, 0x7b, 0x9c, 0xf5, 0x85, 0x07, 0x2d, 0x6b, 0xc6, 0xc1, 0x2e, 0x72, 0x22, 0x5a, 0x43, 0xff, 0x1e, 0xec, 0x67, 0x2b, 0x31, 0x96, 0x14, 0x2c, 0xb1, 0x5f, 0x5d, 0x0c, 0xc9, 0xad, 0x15, 0x5f, 0xab, 0x66, 0x14, 0x1c, 0x72, 0xfa, 0x23, 0xef, 0x9f, 0x77, 0xf6, 0x50, 0xb0, 0x70, 0xb8, 0x3c, 0x85, 0x9e, 0x90, 0x69, 0x17, 0x25, 0xae, 0x6e, 0xe2, 0x16, 0x7d, 0x42, 0x38, 0xdf, 0x74, 0x72, 0x7b, 0x97, 0xa9, 0x9e, 0x40, 0x24, 0x85, 0xdc, 0x64, 0xfa, 0xb1, 0x8b, 0x95, 0xe6, 0xe4, 0x13, 0x72, 0xf1, 0x52, 0x2f, 0xa0, 0xd6, 0x52, 0xc0, 0x11, 0xa7, 0xfe, 0xd5, 0x3b, 0x56, 0xca, 0xbc, 0x01, 0xce, 0x3d, 0xd2, 0x30, 0x97, 0x1d, 0xdc, 0xeb, 0x9d, 0xa9, 0x3e, 0x09, 0xef, 0xee, 0x7f, 0x09, 0x7b, 0x82, 0x43, 0x15, 0x2e, 0xa4, 0x2e, 0x97, 0x21, 0x92, 0x7e, 0x69, 0x21, 0x25, 0xda, 0x46, 0x7c, 0x0c, 0xcd, 0x1d, 0xde, 0x42, 0x11, 0xa2, 0xef, 0xa2, 0xc8, 0x32, 0x9a, 0x82, 0xcf, 0x72, 0x7e, 0x22, 0xa6, 0x11, 0xfa, 0xec, 0x0b, 0x77, 0x99, 0x38, 0x03, 0xf6, 0x80, 0xba, 0xea, 0x75, 0x19, 0xb0, 0x48, 0x02, 0xb2, 0x6b, 0xc0, 0x8c, 0xfb, 0xfe, 0xaf, 0x94, 0x4f, 0x6f, 0xb4, 0xcb, 0x1c, 0x27, 0xf0, 0x41, 0xb6, 0x46, 0x41, 0x68, 0x3d, 0x05, 0x79, 0x6b, 0xcd, 0xb7, 0x20, 0xdc, 0x40, 0x81, 0x58, 0xcb, 0x33, 0xa3, 0xf3, 0x34, 0xdc, 0x63, 0x2d, 0xa5, 0xb5, 0xa1, 0xd1, 0xfd, 0x49, 0x5b, 0x46, 0x94, 0x01, 0xa8, 0xf2, 0xd8, 0x93, 0x2c, 0xbb, 0x57, 0xfe, 0x7c, 0x77, 0x3b, 0x19, 0x6f, 0x3c, 0xaa, 0x23, 0x5b, 0xc0, 0xe7, 0x00, 0x41, 0x97, 0x91, 0xe8, 0x00, 0x12, 0xdf, 0xf6, 0x5c, 0x2e, 0xc6, 0x8e, 0xc6, 0x77, 0x59, 0x78, 0x9b, 0xef, 0x63, 0xb0, 0xd7, 0xbb, 0xc4, 0x0b, 0x60, 0x65, 0x3f, 0xfe, 0xbf, 0x04, 0x3e, 0xae, 0xc2, 0xa5, 0x90, 0xe1, 0x2a, 0x56, 0x3f, 0x4c, 0x3f, 0x7a, 0x7d, 0xda, 0x81, 0x50, 0xea, 0x4c, 0xfe, 0xc3, 0xf8, 0x5c, 0x2b, 0x67, 0xb3, 0x9f, 0x8b, 0x95, 0xda, 0x6f, 0x5d, 0xdd, 0x82, 0x7f, 0x52, 0xa2, 0xcc, 0x57, 0xec, 0xc4, 0x14, 0xd2, 0x4f, 0x1b, 0xcb, 0xea, 0xaf, 0x0e, 0x0f, 0x53, 0xaa, 0x56, 0x63, 0xea, 0x36, 0xa6, 0x89, 0x1a, 0x66, 0xc0, 0x4e, 0xf4, 0x1e, 0x02, 0x43, 0xde, 0xde, 0xc8, 0x9e, 0x88, 0x6e, 0x32, 0xd4, 0xcb, 0x47, 0x24, 0x7c, 0x28, 0x38, 0xd4, 0x95, 0xb6, 0xa3, 0x91, 0x69, 0xc7, 0x8d, 0xfd, 0x15, 0xf5, 0xbf, 0xb1, 0x98, 0x8c, 0x57, 0x51, 0xbf, 0x83, 0x6a, 0x35, 0x10, 0x03, 0x50, 0xe5, 0xf7, 0xfa, 0xf8, 0xa5, 0xb0, 0xdb, 0xfb, 0x42, 0x93, 0xbb, 0x17, 0xf7, 0x36, 0xbe, 0x26, 0x66, 0x61, 0xe2

db 0xaf, 0xe0, 0x22, 0x25, 0x2a, 0xae, 0x78, 0x67, 0x8f, 0x7e, 0x9e, 0x59, 0xd7, 0xa3, 0x71, 0xcc, 0x43, 0x85, 0x09, 0xf9, 0x18, 0x52, 0x7b, 0x01, 0x73, 0xcb, 0x31, 0x18, 0x66, 0x79, 0x67, 0x10, 0x67, 0xd8, 0xdf, 0x43, 0xaf, 0x2d, 0x9a, 0x09, 0x9c, 0xd1, 0x37, 0x7e, 0xf5, 0x1c, 0x3c, 0x4f, 0x15, 0xe1, 0x6f, 0xfd, 0x13, 0x3d, 0x53, 0x81, 0xa9, 0x93, 0x5f, 0x92, 0x41, 0x48, 0xec, 0x87, 0x87, 0x1d, 0x0b, 0xaa, 0xaa, 0xd3, 0xc2, 0x98, 0x20, 0xce, 0x28, 0xaf, 0x9d, 0x84, 0x69, 0x4a, 0xfd, 0xc0, 0x9c, 0x2e, 0x50, 0x20, 0xb2, 0x00, 0xc1, 0x81, 0x2a, 0x32, 0x8e, 0x95, 0x20, 0xa7, 0xca, 0x39, 0x28, 0x12, 0x23, 0x0e, 0x43, 0xd3, 0x82, 0x76, 0x73, 0x3c, 0xbf, 0xa9, 0x98, 0xf6, 0x39, 0x6d, 0xd9, 0x15, 0x33, 0x1e, 0x07, 0x7c, 0x08, 0x12, 0x23, 0xbd, 0xd3, 0x34, 0x2d, 0x9a, 0x23, 0x21, 0x46, 0xf3, 0x9a, 0x04, 0x25, 0x62, 0xeb, 0x7e, 0x9a, 0xaa, 0xb6, 0x26, 0xaa, 0x85, 0x01, 0x3a, 0xd8, 0xfc, 0x57, 0x98, 0xb9, 0xe4, 0xc4, 0xe9, 0x11, 0x3e, 0x22, 0x95, 0x3b, 0x41, 0x2b, 0x02, 0x04, 0x6c, 0x75, 0xa5, 0xf2, 0xaa, 0x09, 0x9e, 0x6f, 0xab, 0x1d, 0x2a, 0x5c, 0xde, 0x21, 0xb1, 0x96, 0x2d, 0x86, 0x3f, 0xd0, 0x07, 0x18, 0x1f, 0x87, 0xc2, 0x8f, 0xdf, 0x6a, 0x57, 0x6d, 0x3f, 0x80, 0xc5, 0x08, 0x19, 0xa5, 0x09, 0x65, 0x3d, 0xdc, 0x9e, 0x80, 0x3c, 0x2a, 0x0e, 0x7a, 0x40, 0x04, 0x0b, 0xcc, 0x61, 0xdb, 0x73, 0xfc, 0xa5, 0x0a, 0x42, 0x18, 0xc1, 0xd5, 0xbd, 0x18, 0x78, 0xa1, 0xe4, 0xde, 0x44, 0xec, 0x79, 0xb0, 0x27, 0xaa, 0x45, 0x21, 0x57, 0x19, 0x75, 0x09, 0x5c, 0x58, 0xd5, 0xb9, 0x6f, 0x3b, 0x48, 0x59, 0x41, 0x3e, 0xfd, 0x17, 0x43, 0x27, 0xc3, 0x8d, 0x76, 0x8e, 0x38, 0x47, 0xe7, 0xd2, 0xea, 0x54, 0x73, 0x8a, 0x65, 0x4c, 0x49, 0x91, 0xaf, 0x29, 0x65, 0x0d, 0x81, 0xa4, 0x77, 0xd7, 0x32, 0xd0, 0x69, 0xd9, 0x6b, 0xa3, 0x9b, 0x24, 0xd6, 0x0a, 0xd2, 0x77, 0x38, 0x59, 0x0b, 0xc8, 0x5c, 0xc7, 0x0b, 0x1d, 0xd1, 0xfa, 0xa7, 0x45, 0x3c, 0xeb, 0x5c, 0x8e, 0x25, 0x35, 0x81, 0x6d, 0x6d, 0xfe, 0xb4, 0x63, 0x89, 0xe4, 0xf0, 0xa8, 0xda, 0xb7, 0xd4, 0xff, 0x5d, 0x28, 0x97, 0x11, 0xf9, 0x8d, 0xab, 0x29, 0xd5, 0xd3, 0x1c, 0x70, 0x20, 0x4c, 0x41, 0x16, 0x42, 0xfd, 0xfc, 0x62, 0x82, 0x40, 0x59, 0x34, 0x28, 0xd0, 0xd5, 0xfc, 0xac, 0x97, 0xb8, 0x82, 0x0e, 0x4b, 0xae, 0x51, 0x28, 0x1a, 0xf1, 0x87, 0xd3, 0x20, 0xa3, 0xe7, 0x74, 0x69, 0x3c, 0x54, 0x8d, 0xc5, 0x56, 0x1d, 0xcd, 0x75, 0xae, 0x88, 0x17, 0x30, 0xdf, 0x46, 0x4a, 0xbc, 0x64, 0xff, 0xa2, 0xc1, 0x62, 0xbd, 0x88, 0x7b, 0x3e, 0xa1, 0x0c, 0xa9, 0x13, 0x0e, 0xc1, 0xb4, 0x24, 0xe6, 0x96, 0x1b, 0x9c, 0x9b, 0xac, 0x44, 0x33, 0x5b, 0xda, 0xd5, 0x88, 0x4d, 0xfe, 0x81, 0x09, 0x07, 0x17, 0xcf, 0x14, 0x05, 0xaf, 0xf8, 0x72, 0x14, 0x49, 0x5f, 0x06, 0x62, 0xab, 0xe0, 0x42, 0x70, 0x12, 0x59, 0x41, 0x0f, 0x18, 0x83, 0x68, 0x6d, 0xc6, 0x3c, 0xea, 0xe0, 0x6d, 0xd4, 0xae, 0xa6, 0xf1, 0x63, 0x21, 0x7f, 0xb5, 0x9d, 0x22, 0xf4, 0xd2, 0x49, 0x49, 0xed, 0x07, 0xb1, 0x11, 0xf9, 0x2e, 0x74, 0xbe, 0x35, 0x47, 0xdc, 0xef, 0x85, 0x0b, 0x4d, 0x46, 0xe6, 0x1f, 0x60, 0x6a, 0xa1, 0x8a, 0x4d, 0x46, 0x87, 0x30, 0x8e, 0x9a, 0xba, 0x97, 0x3e, 0x15, 0xb7, 0x33, 0x76, 0x81, 0x69, 0xdb, 0x82, 0x5e, 0xe6, 0x7b, 0xec, 0xd2, 0x80, 0x7f, 0x17, 0xf1, 0x73, 0xe2

.data_mid:
db 0xd7, 0xa9, 0x35, 0x61, 0x5f, 0xb8, 0xb6, 0x2d, 0x29, 0x34, 0x63, 0xbf, 0xe2, 0x1c, 0x34, 0xe9, 0xf5, 0xff, 0x34, 0x8a, 0x2f, 0xea, 0xd4, 0x3f, 0x3b, 0xfe, 0x6e, 0xdf, 0xa6, 0xd8, 0xc6, 0xb8, 0xc5, 0xff, 0x12, 0x97, 0x53, 0xda, 0x86, 0xa8, 0x0a, 0x12, 0x4e, 0x5d, 0x96, 0x65, 0x51, 0x22, 0xe2, 0x9d, 0x08, 0x71, 0x84, 0x19, 0x8b, 0xbf, 0x29, 0xd3, 0x3f, 0xab, 0xde, 0xe4, 0x27, 0x8b, 0x99, 0xcc, 0xb1, 0x7c, 0xa5, 0x71, 0x91, 0x9a, 0x0b, 0xad, 0x75, 0x86, 0xe3, 0x9c, 0x4e, 0x0c, 0x01, 0xb3, 0x12, 0x33, 0x90, 0x81, 0x7c, 0x71, 0x2c, 0x70, 0x61, 0xd5, 0x39, 0x0c, 0x45, 0xfc, 0x27, 0xaf, 0xbb, 0xd9, 0x26, 0x1b, 0x33, 0xb4, 0x0d, 0xf8, 0xd6, 0x2d, 0x09, 0xc7, 0x8c, 0xbf, 0x48, 0x53, 0x14, 0x94, 0x76, 0x25, 0xc7, 0x0c, 0x69, 0x49, 0x82, 0xb4, 0x2f, 0x48, 0x38, 0x44, 0x9d, 0x90, 0x6d, 0x66, 0x35, 0xe9, 0x3e, 0x2f, 0x2a, 0xb7, 0xe1, 0xb1, 0x2b, 0x99, 0x08, 0x6f, 0x5c, 0x6c, 0xdf, 0xdb, 0x10, 0xe2, 0xaa, 0x86, 0xe7, 0xf8, 0x9e, 0x62, 0xde, 0xa5, 0x81, 0x6b, 0x20, 0x47, 0xa9, 0x06, 0x49, 0xc0, 0x78, 0x8c, 0x70, 0x93, 0x7e, 0xda, 0xda, 0x5e, 0x3b, 0x23, 0xf9, 0xcc, 0x87, 0xdf, 0x48, 0x4f, 0xd6, 0x77, 0xce, 0x45, 0xe1, 0xdc, 0x0c, 0x7a, 0x0c, 0x50, 0x15, 0x63, 0x8c, 0x48, 0xd3, 0x8e, 0xfa, 0xcc, 0xac, 0x1a, 0x83, 0xde, 0xb1, 0x87, 0x2a, 0x58, 0x5c, 0xa5, 0x20, 0x3d, 0xaa, 0x1e, 0x5d, 0x71, 0xa6, 0x57, 0x75, 0x82, 0xb7, 0x33, 0x9e, 0x6b, 0xf3, 0x35, 0x02, 0x98, 0x03, 0xe1, 0x3b, 0xd2, 0x9f, 0x7a, 0x06, 0x85, 0xef, 0x7d, 0xd9, 0xf2, 0x0c, 0x9e, 0xce, 0xb9, 0xce, 0x13, 0x4a, 0x9e, 0x8a, 0x29, 0xe6, 0xe5, 0xe4, 0x39, 0xba, 0xfd, 0xa3, 0x33, 0xa8, 0x13, 0x9e, 0xa5, 0x11, 0x37, 0x69, 0xbc, 0xda, 0x11, 0x49, 0x2d, 0x4a, 0xef, 0x20, 0x8b, 0x7a, 0xb8, 0x9c, 0xc3, 0xaf, 0x26, 0x71, 0xd9, 0xa2, 0xf6, 0x0f, 0x85, 0x87, 0xa8, 0x6c, 0xf9, 0x99, 0xa2, 0xb2, 0x36, 0x2d, 0x78, 0x10, 0xe4, 0x33, 0x8d, 0xa4, 0x63, 0xea, 0x02, 0xb9, 0xac, 0x2f, 0x90, 0x39, 0x2d, 0x0e, 0x2e, 0xf5, 0x08, 0xa5, 0x5c, 0x8e, 0x71, 0x30, 0x0d, 0x1b, 0x84, 0x7a, 0xd7, 0xd4, 0xab, 0x81, 0x82, 0x18, 0x37, 0xf3, 0x28, 0x6f, 0x4e, 0x28, 0x71, 0xda, 0xc9, 0x99, 0x46, 0x14, 0x46, 0x77, 0x01, 0x16, 0x21, 0xae, 0x83, 0x93, 0x86, 0x7f, 0x5a, 0xee, 0xd5, 0xdf, 0x48, 0x5b, 0x15, 0xc8, 0x09, 0x30, 0x8f, 0x01, 0xcc, 0x95, 0x30, 0xd9, 0xf7, 0x72, 0x97, 0xfd, 0x9d, 0xec, 0x9f, 0xbf, 0x5c, 0xbf, 0x4f, 0xca, 0x33, 0xb4, 0xd2, 0xa2, 0xb9, 0x08, 0x9c, 0x40, 0x25, 0x3f, 0x86, 0xdc, 0x83, 0x70, 0x2f, 0xfb, 0x2a, 0xf8, 0x61, 0x1f, 0xa1, 0x1f, 0x36, 0x04, 0xe2, 0xef, 0x1c, 0xa4, 0xcd, 0x3c, 0x7f, 0xc5, 0x73, 0x9c, 0x2e, 0xeb, 0x03, 0x79, 0xd1, 0x02, 0xfc, 0x6f, 0xbd, 0x5a, 0x95, 0xb2, 0xf6, 0x25, 0x96, 0xe6, 0x80, 0x0a, 0xc5, 0xc7, 0xca, 0x8d, 0x31, 0xae, 0xf0, 0x49, 0xcf, 0x43, 0x06, 0x27, 0x7f, 0x25, 0xc7, 0x4c, 0xb7, 0xfc, 0x73, 0xd3, 0x04, 0xd3, 0xb9, 0x9f, 0x74, 0xed, 0x9e, 0x3c, 0xf0, 0xcf, 0x26, 0x2b, 0xd9, 0xcb, 0x78, 0x2a, 0xef, 0x72, 0xf7, 0xb6, 0x78, 0x30, 0x2d, 0x8c, 0x83, 0x73, 0x66, 0x74, 0x3d, 0x66, 0x0a, 0x74, 0x5a, 0x3f, 0x9f, 0x6e, 0x56, 0x68, 0x01, 0xc2, 0xca, 0x2b, 0xa1, 0x25, 0x36, 0x9c, 0x3b, 0xa4, 0x5e, 0x44, 0xf1, 0x18, 0x1d, 0xb6, 0x1a, 0x3a, 0xee, 0x8d, 0x67, 0x34, 0x9c

db 0xdd, 0x48, 0x14, 0xc2, 0x5f, 0xd8, 0xe5, 0x71, 0x22, 0xbf, 0xbc, 0x84, 0xda, 0xc1, 0xb1, 0x22, 0x55, 0xa4, 0x63, 0x41, 0x77, 0xac, 0x40, 0x2d, 0x44, 0x73, 0x8c, 0x14, 0xba, 0x5e, 0x63, 0x68, 0x65, 0x61, 0x6d, 0xec, 0xe2, 0x6d, 0x37, 0x22, 0x04, 0xeb, 0xc7, 0xd4, 0xc9, 0x62, 0x56, 0x13, 0x96, 0x29, 0x03, 0xf4, 0x55, 0xe2, 0x58, 0x7d, 0xda, 0x52, 0x2e, 0x94, 0x07, 0xe6, 0xef, 0xc0, 0xee, 0x9e, 0x0b, 0xf7, 0xcd, 0x13, 0x8b, 0x7d, 0xea, 0xdc, 0xf8, 0xf1, 0xcb, 0xad, 0x49, 0x97, 0xc9, 0x98, 0x0b, 0xcf, 0x84, 0x8e, 0x8e, 0xbb, 0x06, 0x2e, 0x54, 0xf5, 0xa7, 0xbd, 0x70, 0x7e, 0x38, 0x69, 0x8d, 0xb0, 0x01, 0x7b, 0x41, 0x80, 0x09, 0x44, 0xfd, 0x7e, 0x21, 0xb4, 0xbe, 0x6b, 0x4a, 0xb7, 0xca, 0x2d, 0x19, 0xfe, 0x6d, 0xd6, 0x11, 0x29, 0xbb, 0xb2, 0x16, 0xf1, 0xe7, 0x92, 0x71, 0xda, 0x7e, 0x68, 0x3a, 0xe0, 0xea, 0x89, 0x8d, 0xe0, 0x44, 0x48, 0x25, 0x92, 0x37, 0x54, 0x26, 0xf2, 0xab, 0xb3, 0x3b, 0xdb, 0xbb, 0x2b, 0x5c, 0xf5, 0xbc, 0xc7, 0x97, 0xdb, 0xc7, 0x49, 0x25, 0x7c, 0xc2, 0x80, 0x02, 0x69, 0xd4, 0xda, 0xda, 0xe1, 0x04, 0xf3, 0x19, 0xb8, 0xc9, 0xb2, 0xfb, 0x1e, 0x47, 0xa9, 0x0c, 0xa3, 0x48, 0xce, 0xc2, 0x9e, 0x3b, 0x28, 0x23, 0x5a, 0x20, 0x44, 0x77, 0x40, 0xe2, 0xd7, 0x20, 0xd5, 0x71, 0x6f, 0xd4, 0x3c, 0x68, 0x38, 0x9b, 0x89, 0x2e, 0x2d, 0xa8, 0x1f, 0x99, 0xb5, 0x8a, 0x66, 0x07, 0x59, 0x75, 0x9e, 0xf8, 0xd9, 0xbe, 0x85, 0x6a, 0x20, 0x92, 0x9d, 0xd2, 0x5e, 0x45, 0xc0, 0x60, 0xbe, 0x85, 0x0b, 0x84, 0x47, 0xf5, 0xa8, 0x43, 0x87, 0xf1, 0x21, 0x21, 0xb0, 0x3b, 0x04, 0x13, 0x16, 0x3e, 0xdf, 0xc3, 0xc6, 0x04, 0x73, 0xcd, 0x92, 0x76, 0xfb, 0xe7, 0x9c, 0xd3, 0x46, 0x11, 0x78, 0xca, 0x12, 0xd9, 0x4a, 0x35, 0xf1, 0x6e, 0x89, 0x8b, 0xe9, 0x7a, 0x04, 0xba, 0x18, 0x25, 0x7c, 0x9e, 0xe6, 0x4f, 0xc2, 0x56, 0x05, 0x72, 0xc3, 0x76, 0xee, 0x7d, 0x77, 0x19, 0x7a, 0x73, 0x2c, 0x81, 0xb8, 0xc7, 0xd9, 0x7f, 0x17, 0x5d, 0x30, 0xda, 0x77, 0x3c, 0x14, 0x88, 0xe8, 0xe4, 0xbf, 0xee, 0x21, 0x1c, 0x29, 0x4e, 0x58, 0xa8, 0x8a, 0x5c, 0xae, 0xa2, 0x1c, 0x7c, 0x25, 0x7c, 0x1c, 0x39, 0xa4, 0x28, 0x4b, 0x78, 0x52, 0xae, 0x2c, 0xbb, 0x5f, 0xbf, 0x51, 0x09, 0x20, 0x76, 0xb2, 0x7d, 0xb1, 0x63, 0x84, 0xc5, 0x49, 0x8a, 0x73, 0xdb, 0x76, 0x1d, 0x25, 0x31, 0xf2, 0x1e, 0x19, 0x38, 0xc8, 0x3b, 0x51, 0x3c, 0x13, 0x52, 0x84, 0xae, 0xc2, 0xe4, 0x8a, 0x57, 0x0d, 0xde, 0x8d, 0x18, 0x48, 0x9a, 0xbd, 0xbf, 0xf3, 0xea, 0x79, 0x17, 0x06, 0x96, 0x72, 0x08, 0x60, 0x95, 0xf9, 0x6f, 0x25, 0x0c, 0xb7, 0x9d, 0x98, 0x23, 0x01, 0xc8, 0x7a, 0xdb, 0x75, 0x63, 0x64, 0x14, 0x5e, 0x10, 0xf5, 0x16, 0x48, 0xbc, 0xc6, 0x7e, 0x24, 0xf3, 0xad, 0x57, 0x3f, 0x7d, 0x6c, 0xab, 0x18, 0x8c, 0x12, 0xc5, 0x0c, 0xd8, 0xb5, 0x1e, 0x43, 0x7c, 0x23, 0x17, 0x48, 0xba, 0x76, 0x3b, 0xd9, 0x2b, 0xae, 0x1b, 0xef, 0x58, 0xfa, 0x87, 0xad, 0x9b, 0x6d, 0xf9, 0xab, 0xa8, 0x3c, 0xfc, 0x59, 0x67, 0xa6, 0x2c, 0xc7, 0x75, 0xa4, 0x97, 0xca, 0x18, 0x18, 0x04, 0x2c, 0xb3, 0x0e, 0xa9, 0x69, 0x33, 0x67, 0xa2, 0xc6, 0xbc, 0x98, 0x48, 0x71, 0x11, 0x05, 0x30, 0xf6, 0xa9, 0x61, 0x40, 0x46, 0xf1, 0x41, 0x37, 0xd0, 0x6b, 0x7c, 0x1f, 0x03, 0x5c, 0xe9, 0xf4, 0x59, 0x1d, 0x35, 0xf0, 0x98, 0x42, 0x4a, 0x92, 0x2a, 0xc3, 0x9a, 0xb8, 0xa5
