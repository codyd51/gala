.text

.extern _c_entry_point

.pool
.set printf, 0x8001b25c

.code 16
_start: .global _start
    push {lr}

    @ Preserve registers
    @push {r0-r11}

    @push {r6}
    @push {r7}
    @push {r8}

    @push {r3}
    @push {r4}
    @push {r5}

    @push {r0}
    @push {r1}
    @push {r2}

    adr r0, intro
    mov r1, lr
    ldr r8, =printf
    blx r8

    pop {pc}

    pop {r3}
    pop {r2}
    pop {r1}

    adr r0, msg1
    blx r11

    pop {r3}
    pop {r2}
    pop {r1}

    adr r0, msg1
    blx r10

    pop {r3}
    pop {r2}
    pop {r1}

    adr r0, msg1
    blx r10

    @ Restore registers
    pop {r0-r11}

    pop {pc}

.align 2
intro:
.asciz "\nRegdump@ 0x%08x\n\0"

msg1:
.asciz "0x%08x\n0x%08x\n0x%08x\n\0"
