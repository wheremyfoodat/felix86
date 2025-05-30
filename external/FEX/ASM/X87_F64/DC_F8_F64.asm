%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x4000000000000000",
    "RBX": "0x4010000000000000"
  },
  "Env": { "FEX_X87REDUCEDPRECISION" : "1" }
}
%endif
bits 64

lea rdx, [rel data]
fld tword [rdx + 8 * 0]

lea rdx, [rel data2]
fld tword [rdx + 8 * 0]

fdiv st1, st0

fstp qword [rdx]
mov rax, [rdx]
fstp qword [rdx]
mov rbx, [rdx]

hlt

align 8
data:
  dt 8.0
  dq 0
data2:
  dt 2.0
  dq 0
