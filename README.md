# Secured Routines: Language-based Construction of Trusted Execution environments.

# Description

This repository is a snapshot of GOTEE, a research prototype compiler based on the [Go programming language](https://github.com/golang/go).
The corresponding research paper was accepted at [ATC19](https://www.usenix.org/conference/atc19).

## Abstract

Trusted Execution Environments (TEEs), such as Intel SGX enclaves, use hardware to ensure the confidentiality and integrity of operations on sensitive data. While the technology is available on many processors, the complexity of its programming model and its performance overhead have limited adoption. TEEs provide a new and valuable hardware functionality that has no obvious analogue in programming languages, which means that developers must manually partition their application into trusted and untrusted components.

This paper describes an approach that fully integrates trusted execution into a language. We extend the Go language to allow a programmer to execute a goroutine within an enclave, to use low-overhead channels to communicate between the trusted and untrusted environments, and to rely on a compiler to automatically extract the secure code and data.
Our prototype compiler and runtime, GOTEE , is a backward-compatible fork of the Go compiler.

The evaluation shows that our compiler-driven code and data partitioning efficiently executes both microbenchmarks
and applications. On the former, GOTEE achieves a 5.2× throughput and a 2.3× latency improvement over the Intel
SGX SDK. Our case studies, a Go ssh server, the Go tls package, and a secured keystore inspired by the go-ethereum
project, demonstrate that minor source-code modifications suffice to provide confidentiality and integrity guarantees with
only moderate performance overheads.

## Disclaimer

GOTEE is a research prototype, developed by Adrien Ghosn as part of his PhD at EPFL (Switzerland).
The code is **not** production-ready and comes with no guarantees. 
Furthermore, the original repository for GOTEE is an ongoing project.
As a result, APIs, semantics, and features migh change.
We will update this snapshot everytime a milestone is reached.

Gotee only supports linux x86 platforms.

## Compiling and installing Gotee

Gotee has one dependency on a [serializer](https://github.com/aghosn/serializer), required to communicate with the Intel AESM module. This package must be installed and the `serializer` command available in your shell environment (`go install` command).

Moreover, you need to have an SGX enabled processor with the Intel AESM enclave running (for more information about how to set up Intel SGX, go to Intel SGX SDK [repositories][https://github.com/intel/linux-sgx]).
The Intel SGX SDK itself is not required.

Gotee requires a valid `go` install on the target machine to bootstrap the compilation.

To compile Gotee, simply use `make` in the root directory of this folder.
This will trigger the bootstrap compilation and install Gotee as a system command called `gotee`.
The `make clean` command allows to uninstall `gotee`.
The scripts try to install Gotee under `/usr/local/bin` using a symbolic link.
You might have to change access rights to this folder in order to let the script install the command.


## Example

A hello-world example is included in this repository under `example/hello-world`.
A detailed README is available in this folder.

## Ongoing changes

Due to a late refactoring and the prototype nature of the compiler, Gotee temporarily prevents using `gosecure` on functions declared in the main package, and using `gosecure` outside of the `main` package.
This restrictive behavior was introduced during a code-refactoring that aimed at cleaning up the implementation, and will be fixed.

## Benchmarks

We are working on cleaning the benchmarks used in the paper and making them open-source as well.

https://github.com/epfl-dcsl/gosecure-benchmarks


