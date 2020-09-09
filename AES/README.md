# AES Implementation

## Compiling
Simply type `make`, and the Makefile should handle everything. This program uses C++11, so if there are any issues, make sure that your machine has a C++11 compiler. It has been tested and works on the Min Kao Hydra machines.

## Running
`./AES-Worker Run-Tests|FIPS-Appendix-C|Encrypt|Decrypt [BLOCK] [KEY]`
This program can encrypt or decrypt any 128 bit block using a 128|192|256 bit key from the command line. There are built-in unit tests that can be run by calling `./AES-Worker Run-Tests`, but to only run the FIPS Appendix C cases, run `./AES-Worker FIPS-Appendix-C`.
