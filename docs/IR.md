# felix86 intermediate representation

The intermediate representation goes through a few stages.

First, the frontend emits IR that works using multiple get_guest/set_guest instruction.

A get_guest indicates a guest register should be loaded into a temporary.
For example:
`t0 = get_guest(rax)`
loads the full 64-bit value of rax into t0.

get_guest only operates on the full versions of the registers. There's no get_guest(eax), that would happen through the use of a mask:
```
t0 = get_guest(rax)
t1 = 0xFFFFFFFF
t2 = t0 & t1
```

set_guest is the opposite:
```
set_guest(rax, t0)
```
sets the full 64-bit value of t0 into rax

## Static Single Assignment
The existance of set_guest/get_guest means that the IR is not in SSA form.
For example consider the x86-64 code:
```
mov rax, 5
add rax, 1
add rbx, rax
add rbx, rax
```
this may be converted into something like:
```
t0 = 5
set_guest(rax, t0)
t1 = get_guest(rax)
t2 = 1
t3 = t1 + t2
set_guest(rax, t3)
t4 = get_guest(rbx)
t5 = get_guest(rax)
t6 = t4 + t5
set_guest(rbx, t6)
jmp rcx
```
In this case, rax is set multiple times and is essentially treated as a variable.
To convert into SSA, get_guest will simply copy the last set_guest/get_guest. If there's no last set_guest/get_guest, only then will it be converted into a load_guest_from_memory instruction, which will do a memory read into the guest struct.

set_guest's will all be optimized into a simple copy operation (such as `t0 = t1`), which will be copy propagated away later.

Finally, on all the function exits, the value of the last set_guest for each guest register will be used for a store_guest_to_memory, which will writeback the value to the guest struct.

These (load_guest_from_memory/store_guest_to_memory) can't be optimized away. The function will need to read/write to the guest struct at some point, because the recompiler will need to exit the running state and writeback any registers changed to the struct.

Our new code would look like this:
```
t0 = 5
t1 = t0                             // from set_guest
t2 = t1                             // from get_guest
t3 = t2 + t0
t4 = t3                             // from set_guest
t5 = load_guest_from_memory rbx
t6 = t4                             // from get_guest, t4 is latest set_guest on rax
t7 = t6 + t5
t8 = t7
store_guest_to_memory rax, t4
store_guest_to_memory rbx, t8
t9 = load_guest_from_memory rcx
jmp t9
```