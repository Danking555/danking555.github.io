---
title: "Making Volatility 15x Faster: Lessons from Reverse Engineering Windows Internals"
date: "2025-01-26"
author: "Daniel Davidov"
draft: false
---

## Quick TL;DR
By locating the kernel base address from ```PROCESSOR_START_BLOCK``` rather than scanning for ```KDBG```, I reduced Volatility's analysis time from **~15 seconds to about a second** on a 32GB RAM sample.

Important: This method works only on x64 systems with no virtualization. Otherwise, we gracefully fall back to ```KDBG``` scanning.
## Introduction and summary
Volatility and Memprocfs are two tools for Memory Forensics, but they're implemented differently.
I noticed that Memprocfs parses the RAM file almost instantaneously while Volatility takes longer to analyse the file. 
So, I've conducted a test:
1. I've extracted the RAM from my 32GB system using Winpmem.
2. I've ran the pslist plugin of Volatility3 twice and started a timer each time.
    * The first time took __51 seconds__ - the download of ntoskrnl symbol files took time.
    * The second time took __15 seconds__. 
3. I've ran Memprocfs on the same RAM file, entered the folder that show the processes list. The process list showed up immediately-after __about a second__.

During Incident Response fast processing times of artifacts is crucial. Therefore, I decided to Reverse Engineer the tools to understand how they work and how I can improve Volatility analysis speed. 

At first, I assumed that Memprocfs is faster because it's built in C, meanwhile Volatility is built in Python.
However, during the Reverse Engineering process I learned the algorithm used by Memprocfs and implemented it inside Volatility.
After the changes I've made, I've conducted a similar test on the same aforementioned 32GB RAM file.
1. The first time took __32 seconds__ - all symbols of ntoskrnl were downloaded.
2. The second time took __about a second__. 

The new algorithm is based of an undocumented structure called ```PROCESSOR_START_BLOCK``` that exists only on x64 bit systems with no virtualization and no emulation.  
Additionally, it exists in the first **1MB** of physical memory and has a well defined signature.
On the other hand, the previous algorithm was based on heuristics of scanning for the ```KDBG``` structure, not necessarily existing at the beginning of the RAM file.
with my new implementation, if Volatility is running against memory from x32 machine, a virtual machine or emulated machine, the algorithm will gracefully fall to the ```KDBG``` method.
You can see the changes I've made in the [merged PR inside Volatility][0].
During the Reverse Engineering process I've decided to learn and understand how the algorithm works by [reimplementing the process list extraction in Python][1]. 
It is only for my learning purposes and **should not** be used in production!
However, you can benefit from the newly implemented feature inside Volatility! :)

[0]: <https://github.com/volatilityfoundation/volatility3/pull/1566>
[1]: <https://github.com/Danking555/Rampy>

## Technical overview
**During the debug process, I noticed that the _```"KDBG"```_ scan takes most of the time.**
How do I know that? Let's start the Reverse Engineering process.
### Volatility3 Reverse Engineering
To begin analysing the memory we need to get it first. What I like to do is to run [```Memprocfs```][2] using the command line ```memprocfs -device pmem``` which mounts a new Virtual File System as drive ```M:```, having the RAM file in ```M:\memory.pmem```. 
That way, I'll be able to consult the information from live memory parsed by ```memprocfs```.
So to test ```Volatility3``` I specified the following command line in the ```Pycharm``` debugger: ```python vol.py -f M:\memory.pmem windows.pslist.PsList```.
After running, a lot of debugging prints started to show up in the console, indicating that the specified memory file is scanned, and it took a lot of time. 
So, I've decided to understand what is the function that is responsible for the scan by sending an interrupt ```Ctrl+C``` that will make the python console print the call stack. 
And indeed, you can see in the following snippet that the code is "stuck" in ```data = self._file.read(length)```. 


![](images/1determine_scan_blocker.png)

[2]: <https://github.com/ufrisk/MemProcFS>


Following the call stack in the snippet, we see that a function that's called ```self.determine_valid_kernel``` calls to ```valid_kernel = method(self, context, vlayer, progress_callback)``` which eventually calls ```method_kdbg_offset```.

Let's dig in. The aforementioned function ```"determine_valid_kernel"``` iterates over a list of methods that try to detect "a valid kernel" (assigned to variable ```valid_kernel```).
```python
    valid_kernel: Optional[ValidKernelType] = None
        for virtual_layer_name in potential_layers:
            vlayer = context.layers.get(virtual_layer_name, None)
            if isinstance(vlayer, layers.intel.Intel):
                for method in self.methods:
                    valid_kernel = method(self, context, vlayer, progress_callback)
                    if valid_kernel:
                        break
        if not valid_kernel:
            vollog.info("No suitable kernels found during pdbscan")
        return valid_kernel
    ...
    ...
    ...
    # List of methods to be run, in order, to determine the valid kernels
    methods = [
        method_kdbg_offset,
        method_module_offset,
        method_fixed_mapping,
        method_slow_scan,
    ]
```

So if, for example we implement our own method to populate the variable ```valid_kernel```, ```method_kdbg_offset``` won't be called and the whole process should be much faster. 

Wait, but wait, what should ```"valid_kernel"``` structure contain?

If we continue to analyze the code stack and the code statically we'll see that ```determine_valid_kernel``` calls to ```method_kdbg_offset``` which calls to ```_method_offset(context, vlayer, b'KDBG', 8, progress_callback)``` that essentialy:
1. Scans for ```b'KDBG'``` bytes (```_KDDEBUGGER_DATA64->OwnerTag```) - a process which takes a lot of time.
2. Determines the kernel base from the structure by reading the field ```_KDDEBUGGER_DATA64->KernBase```.
3. Calls to ```valid_kernel = self.check_kernel_offset(context, vlayer, address, progress_callback)``` where ```address``` is the previously kernel base.

In the snippet below you can see the contents of the ```valid_kernel``` variable after it's populated.
In a nutshell it includes:
1. the kernel base offset in virtual memory. 
2. The name of the pdb file ```ntkrnlmp.pdb``` for the specific kernel version.
3. The offset of the aformentioned name.
4. The GUID that's used to download the pdb file.

![](images/2valid_kernel.png)

So now we know what is the main "time blocker" and how theoretically we can make the program run faster.
We should find the kernel base address and pass it to ```check_kernel_offset``` which initializes the variable ```valid_kernel```.
We are ready to deep dive into how Memprocfs extracts the kernel base offset.

### Memprocfs Reverse Engineering
Before we list the operations that Memprocfs does to find the relevant data about the kernel, let's explain some theory.
Memprocfs relies on "the most undocumented structure" that Alex Ionescu says ([in his talk][3]) that he has seen his entire reverse engineering life - the ```Low Stub```.
The ```Low Stub``` is a tiny little piece of 16 bit code that still lives in 64 bit Windows and it's used in two cases:
1. When you're booting up your processors, it starts in 16 bit Real Mode, moves to 32 bit Protected Mode by the code in ```Low Stub``` and then 64 bit Long Mode.
2. When machine returns from sleep, it starts in 16 bit Real Mode first. The ```Low Stub``` handles the transition to Protected mode, etc..

Because of the allocation policies on modern hardware, the ```Low Stub``` is going to be at 0x1000 most of the times. 
On some PIC systems with a setting "Discard Low Memory" in the BIOS disabled, the ```Low Stub``` won't be at address 0x1000, but rather 0x2000, 0x3000, etc..
The ```Low Stub``` is not only code, but actually the ```PROCESSOR_START_BLOCK``` structure, which has alot of fields, one of them called ```ProcessorState``` of type ```KPROCESSOR_STATE```, which has Symbols and highly documented.
The exciting news is the field ```Cr3``` inside ```KPROCESSOR_STATE```, which holds the address of the ```DTB (Directory Table Base)``` AKA, the page tables that can be used to translate virtual addresses to physical addresses.
* For more information, here's [the talk by Alex Ionescu][4], start at 43:36 and [here are the slides][5], slides 46-49.

[4]: <https://www.youtube.com/watch?v=_ShCSth6dWM>
[5]: <http://publications.alex-ionescu.com/Recon/ReconBru%202017%20-%20Getting%20Physical%20with%20USB%20Type-C,%20Windows%2010%20RAM%20Forensics%20and%20UEFI%20Attacks.pdf>

* For more information about the structures mentioned above see the following reference that seems to be [a leak of Windows NT][6].

[6]: <https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/inc/amd64.h#L3334>
![](images/3cr3.png)
![](images/4processor_start_block.png)

**So basically the process of locating the kernel base and extracting the processes list in Memprocfs goes like this:**
1. Iterate the first 1MB of physical memory, starting from the second page (0x1000).
2. In each iteration, after some performed guard checks (that I document in my code), use the ```PROCESSOR_START_BLOCK``` fields offsets to extract relevant data:
3. read the value at offset 0xa0, locating cr3 (pointing at the DTB/PML4).
4. Additionally, in each iteration, read the value at offset 0x70, locating an address we'll call "kernel_hint" which is an approximate location of the Kernel base.
5. Scans for the location of ntoskrnl PE in 32mb address range beggining from "kernel_hint", scanning in 2MB chunks.
After the scan is finished, it has the **offset of the kernel base**.\
 But for those of you who are curious, here's the process list location and initialization process:
6. Extract the address of the exported function ```"PsInitialSystemProcess"``` from the kernel image in memory.
7. The exported function contains the location of the first _```"_EPROCESS"```_ object.
8. Iterate over the list, applying fuzzing mechanisms to understand the offsets of fields even without symbols.

In the snippet below, which is taken from ```Memprocfs```, you can see the loop that iterates the first 1MB of physical memory, starting from the second page (0x1000):

![](images/5memprocfs_find_low_stub.png)

So now that we know the algorithm of Memprocfs, let's implement our own function.\
Let's call it ```method_low_stub_offset``` and put it in the head of the list, the kernel image base detection should be much faster. And, it should not get to the function ```method_kdbg_offset``` which blocks, because it scans for the ```KDBG``` bytes.
The new method should return a ```"valid_kernel"``` structure.

So essentialy, our new method will try to locate the kernel base via x64 Low Stub in lower 1MB starting from second page (4KB).
If "Discard Low Memory" setting is disabled in BIOS, the Low Stub may be at the third/fourth or further pages.
During the scan a few guard checks are implemented. The code is well documented so I'll not repeat, but note how I validated the offsets of the fields. I've replicated the structures described in [this documentation of ```_PROCESSOR_START_BLOCK```][6] and wrote the following code that prints the offset of the given field within the structure:
```c
void print_diff(ULONG64 field_address, ULONG64 base_address) {
    printf("%d:%x\n", field_address - base_address, field_address - base_address);
}
```

I've put all the constant offsets and signatures well documented [here][7].

[7]: <https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/constants/windows/__init__.py> 

Basically the algorithm as the same as previously mentioned.
The implemented guard statements are similar to those in ```Memprocfs``` except the third:
1. The first 8 bytes of PROCESSOR_START_BLOCK & 0xFFFFFFFFFFFF00FF expected signature for validation is checked: 0x00000001000600E9. It's constructed from:
    a. The block starts with a jmp instruction to the end of the block:
    *   PROCESSOR_START_BLOCK->Jmp->OpCode = 0xe9 (jmp opcode), of type UCHAR
    *   PROCESSOR_START_BLOCK->Jmp->Offset = 0x6XX, of type USHORT

    b. A Completion flag is set to non-zero when the target processor has started:
    PROCESSOR_START_BLOCK->CompletionFlag = 0x1, of type ULONG

2. Compare previously observed valid page table address that's stored in ```vlayer._initial_entry``` with ```PROCESSOR_START_BLOCK->ProcessorState->SpecialRegisters->Cr3``` which was observed to be an invalid page address, so add 1 (to make it valid too).
3. ```PROCESSOR_START_BLOCK->LmTarget & 0x3``` should be 0, meaning the page entry for the kernel entry should be invalid(1st bit of address) and not readable/writable(2nd bit of address).

## Closing Thoughts
Hope you enjoyed reading this as much as I enjoyed implementing it and the community will benefit from this contribution.
Special thanks to the creators and maintainers of the Volatility project and to Ulf Frisk, the creator of Memprocfs.\
Always ask yourself how you can make things run better and be curious how things work, that's how I learned a lot from this work.\
If you have any questions feel free to reach me at ```danieldavidov555@proton.me```.