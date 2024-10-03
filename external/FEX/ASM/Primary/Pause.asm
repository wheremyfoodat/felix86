%ifdef CONFIG
{
}
%endif
bits 64

; Set rcx to an absurd number just incase something terrible occurs since pause = `rep nop`
mov rcx, -1

; Just ensure execution.
pause

hlt
