%ifdef CONFIG
{
  "RegData": {
    "RAX": "1",
    "RBX": "1",
    "RDX": "1"
  }
}
%endif
bits 64

mov cl, 2
mov r15, 0
mov r14, 0x4141414141414000
mov r13, 0xFFFFFFFF40000000
mov r12, 0x4000000000000000

mov rax, 0
mov rbx, 0
mov rdx, 0
mov rsi, 1

shld r14w, r15w, cl
cmovz rax, rsi
shld r13d, r15d, cl
cmovz rbx, rsi
shld r12, r15, cl
cmovz rdx, rsi

hlt
