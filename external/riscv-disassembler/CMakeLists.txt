cmake_minimum_required (VERSION 3.12)
project(riscv-disassembler VERSION 0.0.1)

add_library(rvasm src/riscv-disas.c)
target_include_directories(rvasm PUBLIC src)
