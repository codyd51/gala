from strongarm.macho import VirtualMemoryPointer

from assemble import Instr
from configuration import GALA_ROOT, GalaConfig
from patches import BlobPatch, InstructionPatch, Patch, PatchSet


def get_kernelcache_patches(_config: GalaConfig) -> list[Patch]:
    kernelcache_shellcode_addr = 0x8057A314

    sandbox_callbacks_start = 0x803C5A40
    sandbox_callbacks_end = 0x803C5F20
    zero_fill = b"\0" * (sandbox_callbacks_end - sandbox_callbacks_start)
    sandbox_blob_patch = BlobPatch(address=VirtualMemoryPointer(sandbox_callbacks_start), new_content=zero_fill)
    sandbox_patch = PatchSet(
        name="Neuter sandbox",
        patches=[
            sandbox_blob_patch,
            InstructionPatch.quick(0x803C445E, Instr.thumb_nop(), expected_length=2),
            # Patch out the call to sandbox_mac_policy_register and make it look like it returned zero?
            InstructionPatch.quick(0x803C100A, Instr.thumb("movs r0, #0"), expected_length=2),
        ],
    )
    setuid_patch = PatchSet(
        name="Everyone is root",
        patches=[
            # InstructionPatch.quick(0x8014c502, Instr.thumb("movs r0, #0"), expected_length=2),
            # InstructionPatch.quick(0x8014c696, Instr.thumb("nop"), expected_length=2),
            # InstructionPatch.quick(0x8014cfde, Instr.thumb("nop"), expected_length=2),
            # InstructionPatch.quick(0x8014cfe4, Instr.thumb("nop"), expected_length=2),
            # InstructionPatch.quick(0x8014cfea, Instr.thumb("nop"), expected_length=2),
            # InstructionPatch.quick(0x8014cff0, Instr.thumb("nop"), expected_length=2),
            # InstructionPatch.quick(0x8014cffc, Instr.thumb("cmp r0, r0"), expected_length=2),
            # InstructionPatch.quick(0x8014d070, Instr.thumb("nop"), expected_length=2),
            # InstructionPatch.quick(0x8014d076, Instr.thumb("nop"), expected_length=2),
            # InstructionPatch.quick(0x8014d07c, Instr.thumb("nop"), expected_length=2),
            # kauth_cred_getuid always returns 0
            # This patch causes the device to fail to boot...
            # Logs "AppleSerialMultiplexer: mux::timeGetAdjustmentGated: Forcing time update" once every few seconds forever
            # InstructionPatch.quick(0x8013cb70, Instr.thumb("movs r0, #0"), expected_length=2),
            # Checking retval of `suser`. Instead of `cbnz not_root`, set retval = 0.
            InstructionPatch.quick(0x8014C696, Instr.thumb("movs r0, #0"), expected_length=2),
        ],
    )

    neuter_amfi = PatchSet(
        name="Neuter AMFI",
        patches=[
            # PT: Can't patch this because it's in __common,__DATA, bss which takes up no space on disk (and takes up zero space in the file/has zero 'file data' -- Hopper 'magically' shows XRefs to this region)
            # PE_i_can_has_debugger
            # PT: We might need a shellcode program that sets that var to 1, but how to run it at startup?
            BlobPatch(
                address=VirtualMemoryPointer(0x80966080),
                new_content=(
                    GALA_ROOT
                    / "shellcode_programs"
                    / "kernelcache_set_debug_enabled"
                    / "build"
                    / "kernelcache_set_debug_enabled_shellcode"
                ).read_bytes(),
            ),
            # 0x80966080
            # 0x8026a800
            BlobPatch(address=VirtualMemoryPointer(0x801D5BEA), new_content=bytes([0x90, 0xF3, 0x49, 0xF2])),
            # TODO(PT): These might be unnecessary...
            InstructionPatch.quick(0x803AAEB2, Instr.thumb("nop")),
            InstructionPatch.quick(0x803AAEF4, Instr.thumb("nop")),
            InstructionPatch.quick(0x803AAF14, Instr.thumb("nop")),
            InstructionPatch.quick(0x803AAF28, Instr.thumb("nop")),
            InstructionPatch.quick(0x803C4540, Instr.thumb("b #0x803c454a"), expected_length=2),
        ],
    )

    disable_image3_nor_signature_checks = PatchSet(
        name="Image3NOR patches",
        patches=[
            # Patch comparison of retval for bl maybe_some_kind_of_image_validation
            InstructionPatch.quick(0x8057C800, Instr.thumb("cmp r0, r0"), expected_length=2),
            InstructionPatch.quick(0x8057C7E4, Instr.thumb("cmp r0, r0"), expected_length=2),
            InstructionPatch.quick(0x8057C7F2, Instr.thumb("cmp r0, r0"), expected_length=2),
            InstructionPatch.quick(0x8057C826, Instr.thumb("cmp r0, r0"), expected_length=2),
            InstructionPatch.quick(0x8057C876, Instr.thumb("cmp r0, r0"), expected_length=2),
            InstructionPatch.quick(0x8057C88A, Instr.thumb("cmp r0, r0"), expected_length=2),
            # TODO(PT): Next we have to prevent the baseband update...
        ],
    )

    disable_more_signature_checks = PatchSet(
        name="abc",
        patches=[
            InstructionPatch.quick(0x8057D452, [Instr.thumb("movs r0, #0"), Instr.thumb("movs r0, #0")]),
            # SHSH
            InstructionPatch.quick(0x803AC4FE, Instr.thumb("cmp r0, r0")),
            # CERT
            InstructionPatch.quick(0x803AC560, Instr.thumb("cmp r0, r0")),
            # cmp        r0, #0x0?
            # ite        eq?
            # moveq      r4, r3
            # movne      r4, r2
            InstructionPatch.quick(0x803AA8C0, [Instr.thumb("cmp r0, r0"), Instr.thumb("b #0x803aa8ce")]),
            InstructionPatch.quick(0x803AA904, Instr.thumb("nop")),
        ],
    )

    enable_dev_kmem = PatchSet(
        name="Enable /dev/kmem",
        patches=[
            InstructionPatch.quick(0x8009F7AC, Instr.thumb("movs r3, #1")),
            # Set permission bits
            # InstructionPatch.quick(0x8009f738, Instr.arm("mov.w r4, #0x1b6")),
            BlobPatch(address=VirtualMemoryPointer(0x8009F738), new_content=bytes([0x4F, 0xF4, 0xDB, 0x74])),
            # Need to set group too?
        ],
    )

    enable_task_for_pid_0 = PatchSet(
        name="Enable task_for_pid(0)",
        patches=[
            InstructionPatch.quick(0x8017E552, Instr.thumb("b #0x8017e56c"), expected_length=2),
        ],
    )

    # http://www.it-docs.net/ddata/781.pdf
    sandbox_debug_mode = PatchSet(
        name="SandboxDebugMode",
        patches=[
            InstructionPatch.quick(0x803C4578, Instr.thumb("movs r3, #1"), expected_length=2),
            InstructionPatch.quick(0x803C457A, Instr.thumb("movs r3, #1"), expected_length=2),
        ],
    )

    disable_mac_enforcement = PatchSet(
        name="Disable MAC enforcement",
        patches=[
            BlobPatch(VirtualMemoryPointer(addr), new_content=int(0).to_bytes(4, byteorder="little"))
            for addr in [
                0x8025EF80,
                # 0x8025eff8,
                # 0x8025f020,
                # 0x8025f048,
                # PT: This patch causes the device to fail to boot
                ## 0x8025f070,
                # 0x8025f098,
                # 0x8025f0c0,
                # 0x8025f0e8,
                ##0x8025f110,
                # 0x8025f138,
                # 0x8025f160,
                0x8025F188,
            ]
        ],
    )

    allow_rwx_pages = PatchSet(
        name="Allow RWX pages",
        patches=[
            # Ref: https://www.theiphonewiki.com/wiki/Vm_map_protect_Patch
            # vm_map_protect: The original instruction clears the VM_PROT_EXECUTE bit
            # This basic block is reached from a "tst VM_PROT_EXECUTE bit" branch
            InstructionPatch.quick(0x8003D9FC, Instr.thumb_nop()),
            # Same for vm_map_enter
            InstructionPatch.quick(0x800409E8, Instr.thumb_nop()),
            InstructionPatch.quick(0x80040976, Instr.thumb_nop()),
        ],
    )

    return [
        neuter_amfi,
        # Neuter "Error, no successful firmware download after %ld ms!! Giving up..." timer
        InstructionPatch.quick(0x8080E826, Instr.thumb("b #0x8080e85a")),
        disable_image3_nor_signature_checks,
        disable_more_signature_checks,
        setuid_patch,
        sandbox_patch,
        enable_dev_kmem,
        enable_task_for_pid_0,
        disable_mac_enforcement,
        sandbox_debug_mode,
        allow_rwx_pages,
    ]
