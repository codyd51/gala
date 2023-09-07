.text

.pool
.set FUNC_ADDR_IMAGE3_CREATE_STRUCT,      0x412d
.set FUNC_ADDR_IMAGE3_LOAD_CONTINUE,      0x46db
.set FUNC_ADDR_MEMMOVE,                   0x84dc

.set RELOCATED_PAYLOAD_BASE,              0x84039800
.set RELOCATED_PAYLOAD_SIZE,              1024
.set PAYLOAD_STACK_ADDR,                  0x8403c000
.set MAX_DFU_IMAGE_SIZE,                  0x2c000

.set IMAGE3_LOAD_SP_OFFSET,               0x68
.set IMAGE3_LOAD_STRUCT_OFFSET,           0x64

.extern _c_entry_point

_start:
.code 16
    b   relocate_shellcode
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

relocate_shellcode:
    @ Are we already running from the relocated shellcode?
    mov r1, pc
    sub r1, r1, #4
    ldr r0, =RELOCATED_PAYLOAD_BASE
    cmp r0, r1
    beq continue_relocated

    @ Relocate the payload now
    ldr r2, =RELOCATED_PAYLOAD_SIZE
    ldr r3, =FUNC_ADDR_MEMMOVE
    @ memmove(relocated_payload_addr, pc_base, relocated_payload_size)
    blx r3

    ldr r3, =RELOCATED_PAYLOAD_BASE
    @ THUMB
    add r3, r3, #1
    @ Jump to relocated shellcode
    bx r3

continue_relocated:
    @ Set up a stack
    ldr r0, =PAYLOAD_STACK_ADDR
    mov sp, r0
    @ Jump to ARM for compatibility with the Rust payload, which always targets ARM
    blx continue_arm

.code 32
.align 4
continue_arm:
    @ Our Rust always targets ARM, so switch modes
    blx _receive_and_jump_to_image

.global _image3_load_no_signature_check
_image3_load_no_signature_check:
    push {r4-r7, lr}

    mov r6, r11
    mov r5, r10
    mov r4, r8
    push {r4-r6}

    @ r7 = sp - 018
    add r7, sp, #0x18

    @ sp -= IMAGE3_LOAD_SP_OFFSET
    ldr r4, =IMAGE3_LOAD_SP_OFFSET
    mov r5, sp
    sub r5, r5, r4
    mov sp, r5

    @ *(sp + IMAGE3_LOAD_STRUCT_OFFSET) = 0
    mov r3, #0
    ldr r4, =IMAGE3_LOAD_STRUCT_OFFSET
    add r4, r5, r4
    str r3, [r4]

    @ sp[4] = r2
    str r2, [sp, #0x10]
    @ sp[5] = r1
    str r1, [sp, #0x14]
    @ sp[6] = 0
    str r3, [sp, #0x18]
    @ r6 = *r1
    ldr r6, [r1]

    mov r10, r1
    mov r11, #0

    @ r8 = MAX_DFU_IMAGE_SIZE
    ldr r1, =MAX_DFU_IMAGE_SIZE
    mov r8, r1

    @ r8 = r0[1]
    ldr r2, [r0, #4]
    mov r8, r2

    @ r4 = image3_create_struct(sp + IMAGE3_LOAD_STRUCT_OFFSET, r6, r8, 0)
    mov r0, r4
    mov r1, r6
    ldr r4, =FUNC_ADDR_IMAGE3_CREATE_STRUCT
    blx r4
    mov r4, r0

    @ image3_load_continue()
    ldr r3, =FUNC_ADDR_IMAGE3_LOAD_CONTINUE
    bx r3
