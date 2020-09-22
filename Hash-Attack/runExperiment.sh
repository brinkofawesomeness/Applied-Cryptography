#!/bin/bash
rm Results/Collision/*.csv
rm Results/Pre-Image/*.csv
make

./Hash-Attack Collision 8
./Hash-Attack Collision 16
./Hash-Attack Collision 24
./Hash-Attack Collision 32

./Hash-Attack Pre-Image 8
./Hash-Attack Pre-Image 16
./Hash-Attack Pre-Image 24
./Hash-Attack Pre-Image 32

make clean