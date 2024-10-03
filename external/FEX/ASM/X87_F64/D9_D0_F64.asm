%ifdef CONFIG
{
  "Env": { "FEX_X87REDUCEDPRECISION" : "1" }
}
%endif
bits 64

; Just to ensure execution
fnop
hlt
