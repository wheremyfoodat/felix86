%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x0000000000000053",
    "RBX": "0x0000000000000029",
    "RCX": "0x0000000000000005",
    "RDX": "0x0000000000000009",
    "RSI": "0x000000000000001d",
    "RSP": "0x0000000000000028",
    "RBP": "0x0000000000000020",
    "R8": "0x000000000000005a",
    "R9": "0x0000000000000062",
    "R10": "0x000000000000005a",
    "R11": "0x0000000000000040",
    "R12": "0x0000000000000023",
    "R13": "0x0000000000000005",
    "R14": "0x0000000000000021",
    "R15": "0x000000000000003a"
  }
}
%endif
bits 64

lea r15, [rel .data]

movapd xmm0, [r15 + 16 * 0]
movapd xmm1, [r15 + 16 * 1]
movapd xmm2, [r15 + 16 * 2]
movapd xmm3, [r15 + 16 * 3]
movapd xmm4, [r15 + 16 * 4]
movapd xmm5, [r15 + 16 * 5]
movapd xmm6, [r15 + 16 * 6]
movapd xmm7, [r15 + 16 * 7]
movapd xmm8, [r15 + 16 * 8]
movapd xmm9, [r15 + 16 * 9]
movapd xmm10, [r15 + 16 * 10]
movapd xmm11, [r15 + 16 * 11]
movapd xmm12, [r15 + 16 * 12]
movapd xmm13, [r15 + 16 * 13]
movapd xmm14, [r15 + 16 * 14]
movapd xmm15, [r15 + 16 * 15]

cvttsd2si eax, xmm0
cvttsd2si ebx, xmm1
cvttsd2si ecx, xmm2
cvttsd2si edx, xmm3
cvttsd2si esi, xmm4
cvttsd2si edi, xmm5
cvttsd2si esp, xmm6
cvttsd2si ebp, xmm7
cvttsd2si r8, xmm8
cvttsd2si r9, xmm9
cvttsd2si r10, xmm10
cvttsd2si r11, xmm11
cvttsd2si r12, xmm12
cvttsd2si r13, xmm13
cvttsd2si r14, xmm14
cvttsd2si r15, xmm15

hlt

align 16
; 512bytes of random data
.data:
dq 83.0999,69.50512,41.02678,13.05881,5.35242,21.9932,9.67383,5.32372,29.02872,66.50151,19.30764,91.3633,40.45086,50.96153,32.64489,23.97574,90.64316,24.22547,98.9394,91.21715,90.80143,99.48407,64.97245,74.39838,35.22761,25.35321,5.8732,90.19956,33.03133,52.02952,58.38554,10.17531,47.84703,84.04831,90.02965,65.81329,96.27991,6.64479,25.58971,95.00694,88.1929,37.16964,49.52602,10.27223,77.70605,20.21439,9.8056,41.29389,15.4071,57.54286,9.61117,55.54302,52.90745,4.88086,72.52882,3.0201,56.55091,71.22749,61.84736,88.74295,47.72641,24.17404,33.70564,96.71303
