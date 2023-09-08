<div align="center">
  <img src="assets/readme/spread.png" width="60%">
</div>

**gala** is a jailbreak/tethered downgrade tool that currently supports iOS 4. **gala** implements [limera1n](https://www.theiphonewiki.com/wiki/Limera1n_Exploit) to gain code execution in SecureROM, then gradually boots and compromises the system from there.

**gala** comes with an [extensive write-up](https://axleos.com/blog/exploiting-the-iphone-4-part-1-gaining-entry/) on developing an iOS jailbreak.

**gala** provides the following user-facing features:

* Fully controlled bootchain and IPSW restore process
* Custom boot logos
* Kernel task can be controlled (`task_for_pid(0)`)
* Neutered sandbox
* Neutered code signing
* Any task can be root (`suser() == 0`)
* Enable `/dev/kmem` device file
* Disable FreeBSD MAC enforcement
* Allow RWX pages

<table align="center"> 
    <tr>
        <td><img src="assets/readme/runner.png" width="500px"/></td>
    </tr>
</table>
<table align="center"> 
    <tr>
        <td><img src="assets/readme/ibss_background.png" width="200px"/></td>
        <td><img src="assets/readme/jailbroken_with_gala_alert.png" width="200px"/></td>
        <td><img src="assets/readme/flashing_filesystem.png" width="200px"/></td>
    </tr>
</table>

**gala** implements a generic patching framework that emphasises maintainable and understandable patch sets. 

```python
    InstructionPatch(
        function_name="platform_early_init",
        reason="""
        The original logic loads a memory word to find the value to pass to debug_enable_uarts(). 
        We always want the debug logs to be emitted, so override the value here.
        """,
        address=VirtualMemoryPointer(0x84010b96),
        orig_instructions=[Instr.thumb("ldrb r0, [r4]")],
        patched_instructions=[Instr.thumb("movs r0, #3")],
    )
```

As a glance, the reader of this patch can clearly see exactly what's being replaced, and why.

`InstructionPatch` performs extensive validations to ensure the patch does exactly what's described in the metadata. For example, `InstructionPatch` will validate:

* That the replaced instructions exactly match what's expected in the patch.
* That disassembling the assembled patch instructions exactly matches what's written in the patch (in other words, that Capstone confirms that the in-house assembler produces the correct opcodes).
* That the exact correct number of bytes are patched based on the input and output instructions

Disassembly is performed via [Capstone](https://www.capstone-engine.org). New instructions are assembled with an in-house/ad-hoc assembler.

_Example: Injecting a shellcode program_

```python
    shellcode_addr = VirtualMemoryPointer(0x840000fc)
    BlobPatch(
        address=shellcode_addr,
        new_content=(RESOURCES / "shellcode").read_bytes(),
    )
```

**gala** uses [strongarm](https://github.com/datatheorem/strongarm) for Mach-O parsing during patching. **gala** relies on strongarm to find the appropriate file offset for the provided virtual address.

**gala** also provides `Patch` types that are especially convenient for producing custom iOS distributions. For example, it's straightforward to patch files that only exist within a mounted `.dmg`:

```python
    DmgPatchSet([
        DmgReplaceFileContentsPatch(
            file_path=Path("/private/etc/fstab"),
            new_content="""
                /dev/disk0s1 / hfs rw 0 1
                /dev/disk0s2s1 /private/var hfs rw,suid,dev 0 2
            """.encode()
        ),
        DmgApplyTarPatch(
            tar_path=_RESOURCES / "ssh_additions.tar"
        ),
    ])
```

# Requirements

PT: Perhaps clone sshpass and dpkg as tools/?

* sshpass

There are some misconceptions in your comments that I think could be useful to clear up. 

When exploiting a running system, your goal typically won't be to disable ASLR (which would only impact newly spawned processes), but instead to 'infoleak' where ASLR has placed important things you care about, so you know where to access them. 

Modern devices have mechanisms like KPP/KTRR, though, which make it impossible to modify kernel code anyhow. 

You also propose that CoreGraphics might not be sandboxed. CoreGraphics is a dynamic library which can be loaded into any process. It's _processes_ that are sandboxed, not dynamic libraries, so CoreGraphics can definitely exist in a process that has a sandbox profile applied just fine. 

You also mention that graphics functions might not be sandboxed because they need to access graphics acceleration features. This is a good thought! In fact, the kernel extension that enables hardware graphics acceleration, IOMobileFramebuffer, is accessible from the app sandbox for this very reason. As a point of interest, many vulnerabilities have been discovered in IOMobileFramebuffer over the years -- it's an attractive target specifically because it's reachable from the app sandbox.

Lastly, you mention jailbreaking the sandbox. I know what you mean, but "jailbreaking" typically refers to a series of abilities, such as the ability to control the kernel task, the ability to create RWX pages, the ability to bypass the FreeBSD MAC policies, etc. The ability to bypass sandbox restrictions is only one condition of a jailbreak, and a sandbox escape doesn't imply a full jailbreak. Also, jailbreaking doesn't entirely break "the sandbox" -- it's a selective change that can be applied on a per-process basis.
