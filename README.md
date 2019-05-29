# GOSECURE: TEE support in the go programming language

This fork of the go compiler aims at providing a new keyword, `gosecure`, that allows to spawn routines executing inside a TEE (intel sgx for the moment). 

## What we have so far

1. Generate a separate binary that resides in a different part of the address space and contains code that executes inside the TEE.
2. A way to load and execute (outside of the enclave) this binary in a dedicated thread.
3. Cooperation between the two runtimes.
4. Support for the Intel SGX technology.

## Benchmarks

Work in progress
https://github.com/epfl-dcsl/gosecure-benchmarks

## Paper

https://github.com/epfl-dcsl/gosecure-paper/tree/master/atc19

