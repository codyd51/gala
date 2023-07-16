.text

.extern _c_entry_point

.code 16
_start: .global _start
    push {lr}

    @ Preserve r0
    @mov r8, r0

    adr r0, msg

    push {r7}
    push {r6}
    push {r5}
    push {r4}
    push {r3}
    push {r2}
    push {r1}
    push {r0}
    bl _c_entry_point
    pop {r0}
    pop {r1}
    pop {r2}
    pop {r3}
    pop {r4}
    pop {r5}
    pop {r6}
    pop {r7}
    pop {pc}

.align 2
msg:
.asciz "image_load_memory(%08x, %08x, %08x, %08x, %08x, %08x, %08x)\n\0"
@msg_len = . - msg
