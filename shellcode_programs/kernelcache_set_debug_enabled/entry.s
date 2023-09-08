.text

.pool
.set var, 0x8027986c

.code 16
_start: .global _start
    push {r0-r1}
    ldr r0, =var
    mov r1, #1
    str r1, [r0]
    pop {r0-r1}
    bx lr
