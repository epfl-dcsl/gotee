# Hello World Example

This folder contains a hello-world sample code that executes a print from both the untrusted and trusted domains.

## Compiling

Just type `make` in `example/hello-world/`.
This will generate a `main` executable.
If you have a look at the `Makefile`, you'll see that the command used to compile is `gotee build src/main.go`.
We set the `GOPATH` variable before that to allow importing nested folders (pre-go-module way of doing things).

## Running

Execute the generate program, i.e., `./main`. 
The expected output is: 

```
From an untrusted domain:
Hello World!
From a trusted domain:
Hello World!
```

Executing the script will generate a `enclavebin` binary, i.e., the code and data loaded inside the enclave.
This is just for your convinience, to allow you to inspect what code is loaded inside the enclave.

Optionally, you can run the code in simulation mode like this `SIM=1 ./main`. This allows to run Gotee programs without SGX.

## Comments

As you can see in `src/main.go`, you need to import explicitly the `gosec` package.
As mentionned in the general README, we had to disable `gosecure` calls that target functions defined in main.
We also discourage using the `gosecure` keyword outside of the main package for the moment (see README for more information).
