# felix86
An x86-64 userspace emulator for RISC-V Linux

## Similar projects
felix86 is very early in development. If you want a more complete emulator, use one of the following:

- [FEX](https://github.com/FEX-Emu/FEX)
- [box64](https://github.com/ptitSeb/box64)
- [qemu-user](https://www.qemu.org/docs/master/user/main.html)

## Useful documentation for x86-64 emulators
- [x86-64 instruction reference](https://www.felixcloutier.com/x86/)
- [x86-64 opcode tables](http://ref.x86asm.net/coder64.html)
- [sandpile.org](https://sandpile.org/)
- [An optimization guide for x86 platforms by Agner Fog](https://www.agner.org/optimize/optimizing_assembly.pdf)
- [Intel® 64 and IA-32 Architectures Software Developer’s Manual](https://software.intel.com/en-us/download/intel-64-and-ia-32-architectures-sdm-combined-volumes-1-2a-2b-2c-2d-3a-3b-3c-3d-and-4), the most complete resource however unfortunately it's hard to find what you need sometimes

## Useful documentation for emulator JITs and compilers in general
Do note that I haven't fully read through all of these, most of them were used as references for the parts that were relevant. Some I've yet to read and are ones that I've been told are great and will read in the future.
### Basics
- Background of how an interpreter works
- [Just-in-time compilation](https://en.wikipedia.org/wiki/Just-in-time_compilation)
- [Basic block](https://en.wikipedia.org/wiki/Basic_block)
- [Register allocation](https://en.wikipedia.org/wiki/Register_allocation)
### Moving towards using an IR
- [Intermediate representation](https://en.wikipedia.org/wiki/Intermediate_representation)
- [Three address code](https://en.wikipedia.org/wiki/Three-address_code)
- [Static single assignment](https://en.wikipedia.org/wiki/Static_single-assignment_form), a property of IR that makes some optimizations a lot simpler
- [Register Allocation And Spilling Via Graph Coloring](https://web.eecs.umich.edu/~mahlke/courses/583f12/reading/chaitin82.pdf)
- [Linear scan register allocation](https://web.cs.ucla.edu/~palsberg/course/cs132/linearscan.pdf), as opposed to graph coloring register allocation 
- [Efficiently Computing Static Single Assignment Form and the Control Dependence Graph](https://www.cs.utexas.edu/%7Epingali/CS380C/2010/papers/ssaCytron.pdf), the classical SSA paper, must read
- [A Simple, Fast Dominance Algorithm](http://www.hipersoft.rice.edu/grads/publications/dom14.pdf), generally referred to as the Cooper et al. dominance algorithm, showcases a very simple way of constructing a dominance tree and finding dominance frontiers to place phi nodes
- [A Fast Algorithm for Finding Dominators in a Flowgraph](https://www.cs.princeton.edu/courses/archive/fall03/cs528/handouts/a%20fast%20algorithm%20for%20finding.pdf), referred to as the Lengauer-Tarjan dominance algorithm, another algorithm for finding dominance information, haven't read through it but supposedly a lot less simple than Cooper et al.
- [Simple and Efficient Construction of Static Single Assignment Form](https://link.springer.com/chapter/10.1007/978-3-642-37051-9_6), an alternative way of constructing SSA form
### Optimizations that you can apply on SSA
- [Common subexpression elimination](https://en.wikipedia.org/wiki/Common_subexpression_elimination)
- [Copy propagation](https://en.wikipedia.org/wiki/Copy_propagation), useful for after doing common subexpression elimination
- [Constant propagation](https://en.wikipedia.org/wiki/Constant_folding)
- [Dead store](https://en.wikipedia.org/wiki/Dead_store)
### Cliff Click's research
- [Cliff Click - The Sea of Nodes and the HotSpot JIT](https://www.youtube.com/watch?v=9epgZ-e6DUU)
- [A Simple Graph-Based Intermediate Representation](https://www.oracle.com/technetwork/java/javase/tech/c2-ir95-150110.pdf), the original Sea of Nodes paper
- [https://github.com/SeaOfNodes/Simple](https://github.com/SeaOfNodes/Simple), a Sea of Nodes IR implementation, really detailed and easy to read
- [Global Code Motion Global Value Numbering](https://dl.acm.org/doi/pdf/10.1145/207110.207154), another great resource related to moving out of Sea of Nodes while performing GCN
### These have varying degrees of JITs
- [v8 source code](https://github.com/v8/v8)
- [Dynarmic source code & docs folder](https://github.com/PabloMK7/dynarmic/)
- [Dillonb's n64 source code](https://github.com/Dillonb/n64/tree/master/src/cpu/dynarec/v2)
- [PCSX-Redux source code](https://github.com/grumpycoders/pcsx-redux)
- [Duckstation source code](https://github.com/stenzek/duckstation)
- [Dolphin source code](https://github.dev/dolphin-emu/dolphin)
- Yuzu's & shadPS4 shader recompiler source code, employs most of the Braun et al. Simple and Efficient SSA algorithm linked above


## Other useful documentation
- [How programs get run: ELF binaries](https://lwn.net/Articles/631631/)
- [ELF format specification](http://www.skyfree.org/linux/references/ELF_Format.pdf), really pleasant read
- [System-V ABI - AMD64 Architecture Supplement](./docs/sysv-x86-64.pdf), particularly Chapter 3.4 on Process Initialization and Chapter 5 on Program Loading 