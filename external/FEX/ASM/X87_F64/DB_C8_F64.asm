%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x3ff0000000000000",
    "RBX": "0x0000000000000000",
    "RCX": "0x3ff0000000000000"
  },
  "Env": { "FEX_X87REDUCEDPRECISION" : "1" }
}
%endif
bits 64

mov rdx, 0xe0000000

mov eax, 0x3f800000 ; 1.0
mov [rdx + 8 * 0], eax

fld1
fldz

mov eax, 1
cmp eax, 1

fcmovne st0, st1

fldz
cmp eax, 0
fcmovne st0, st2

fstp qword [rdx]
mov rax, [rdx]
fstp qword [rdx]
mov rbx, [rdx]
fstp qword [rdx]
mov rcx, [rdx]


hlt
