%ifdef CONFIG
{
  "Env": { "FEX_X87REDUCEDPRECISION" : "1" }
}
%endif
bits 64

; Just to ensure execution
ffree st0
ffree st1
ffree st2
ffree st3
ffree st4
ffree st5
ffree st6
ffree st7
hlt
