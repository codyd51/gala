#!/bin/sh

#  compile_payload.sh
#  jailbreak
#
#  Created by Phillip Tennen on 08/07/2023.
#
as -arch armv7 assemble2.s -o asm_payload.o
gcc -c -arch armv7 payload_body.c -ffreestanding -o c_payload.o -mthumb
ld asm_payload.o c_payload.o -U _main -U start -static -o payload
python3 dump_shellcode.py
