%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM0": ["0xBF00000000000000", "0xBFC000003FC00000", "0x0000000000000000", "0x0000000000000000"],
    "XMM1": ["0xBF00000000000000", "0xBFC000003FC00000", "0x0000000000000000", "0x0000000000000000"],
    "XMM2": ["0xBF0000003F800000", "0xBFC000003FC00000", "0x0000000000000000", "0x0000000000000000"],
    "XMM3": ["0xBF00000000000000", "0xBFC000003FC00000", "0x0000000000000000", "0x0000000000000000"],
    "XMM4": ["0xBF00000000000000", "0xBFC000003FC00000", "0x0000000000000000", "0x0000000000000000"],
    "XMM5": ["0xBF00000000000000", "0xBFC000003FC00000", "0x0000000000000000", "0x0000000000000000"],
    "XMM6": ["0xBF0000003F800000", "0xBFC000003FC00000", "0x0000000000000000", "0x0000000000000000"],
    "XMM7": ["0xBF00000000000000", "0xBFC000003FC00000", "0x0000000000000000", "0x0000000000000000"]
  }
}
%endif
bits 64

lea rdx, [rel .data]

vmovaps ymm0, [rdx]
vmovaps ymm1, [rdx]
vmovaps ymm2, [rdx]
vmovaps ymm3, [rdx]
vmovaps ymm4, [rdx]
vmovaps ymm5, [rdx]
vmovaps ymm6, [rdx]
vmovaps ymm7, [rdx]

vroundss xmm0, xmm0, [rdx], 00000000b ; Nearest
vroundss xmm1, xmm1, [rdx], 00000001b ; -inf
vroundss xmm2, xmm2, [rdx], 00000010b ; +inf
vroundss xmm3, xmm3, [rdx], 00000011b ; truncate

; MXCSR
; Set to nearest
mov eax, 0x1F80
mov [rel .mxcsr], eax
ldmxcsr [rel .mxcsr]

vroundss xmm4, xmm4, [rdx], 00000100b

; Set to -inf
mov eax, 0x3F80
mov [rel .mxcsr], eax
ldmxcsr [rel .mxcsr]

vroundss xmm5, xmm5, [rdx], 00000100b

; Set to +inf
mov eax, 0x5F80
mov [rel .mxcsr], eax
ldmxcsr [rel .mxcsr]

vroundss xmm6, xmm6, [rdx], 00000100b

; Set to truncate
mov eax, 0x7F80
mov [rel .mxcsr], eax
ldmxcsr [rel .mxcsr]

vroundss xmm7, xmm7, [rdx], 00000100b

hlt

align 32
.data:
dd 0.5, -0.5, 1.5, -1.5
dd 0.5, -0.5, 1.5, -1.5

.mxcsr:
dq 0, 0
