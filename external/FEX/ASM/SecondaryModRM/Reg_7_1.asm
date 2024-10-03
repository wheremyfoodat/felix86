%ifdef CONFIG
{
  "HostFeatures": ["Linux"]
}
%endif
bits 64

; We can't really check the results of this
; Just ensure we execute it
rdtscp

hlt
