%ifdef CONFIG
{
}
%endif
bits 64

mov rdx, 0xe0000000
clflush [rdx]
hlt
