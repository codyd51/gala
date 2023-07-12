#!/bin/sh

#  compile_payload.sh
#  jailbreak
#
#  Created by Phillip Tennen on 08/07/2023.
#
as -arch armv7 entry.s -o build/entry.o
gcc -c -arch armv7 launch_image.c -ffreestanding -o build/launch_image.o -mthumb -fpic
ld build/entry.o build/launch_image.o -U _main -U start -static -o build/payload_stage1_packed
python3 ../dump_shellcode.py build/payload_stage1_packed build/payload_stage1_shellcode
