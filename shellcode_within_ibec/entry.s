.text

.pool
@.set printf, 0x5ff16940
.set printf, 0x5ff16940

.code 16
_start: .global _start
    push {lr}

    adr r0, intro
    ldr r1, =printf
    blx r1

    pop {pc}

.align 2
intro:
@.asciz "\n***Regdump@ 0x%08x\n\0"
.asciz "\n***Regdump\n\0"
