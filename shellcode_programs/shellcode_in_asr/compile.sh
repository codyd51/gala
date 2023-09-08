#!/bin/sh

#  compile_payload2.sh
#  jailbreak
#
#  Created by Phillip Tennen on 10/07/2023.
#  
as -arch armv7 entry.s -o build/entry.o
gcc -c -arch armv7 body.c -ffreestanding -o build/body.o -mthumb -fpic -fno-stack-protector
ld build/entry.o build/body.o -U _main -U start -static -o build/shellcode_in_asr_packed
python3 ../dump_shellcode.py build/shellcode_in_asr_packed build/shellcode_in_asr_shellcode
