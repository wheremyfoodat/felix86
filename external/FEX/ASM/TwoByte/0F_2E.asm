%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x4700",
    "RBX": "0x0300"
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif
bits 64

mov rdx, 0xe0000000

mov rax, 0x515253543f800000
mov [rdx + 8 * 0], rax
mov rax, 0x5152535440000000
mov [rdx + 8 * 1], rax

mov rax, 0x5152535440800000
mov [rdx + 8 * 2], rax
mov rax, 0x5152535440800000
mov [rdx + 8 * 3], rax

mov rax, 0x515253547FC00000
mov [rdx + 8 * 4], rax
mov rax, 0x5152535440800000
mov [rdx + 8 * 5], rax

movaps xmm0, [rdx + 8 * 0]
ucomiss xmm0, [rdx + 8 * 2]
; 0: CF - 00000001
; 1:    - 00000010
; 2: PF - 00000000
; 3:  0 - 00000000
; 4: AF - 00000000 <- 0
; 5:  0 - 00000000
; 6: ZF - 00000000
; 7: SF - 00000000 <- 0
; ================
;         00000011
; OF: LAHF doesn't load - 0

mov rax, 0
lahf
mov rbx, rax

ucomiss xmm0, [rdx + 8 * 4]
; 0: CF - 00000001
; 1:    - 00000010
; 2: PF - 00000100
; 3:  0 - 00000000
; 4: AF - 00000000 <- 0
; 5:  0 - 00000000
; 6: ZF - 01000000
; 7: SF - 00000000 <- 0
; ================
;         01000111
; OF: LAHF doesn't load - 0

mov rax, 0
lahf

hlt
