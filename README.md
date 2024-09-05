## perf event race condition PoC
This repository demonstrates that the race condition found by Ole (@firzen14) in `perf events` reported to the linux kernel security team is exploitable.  
The PoC gains **multiple writable pages** of UAF kernel memory when it succeeds.

The **patch** for the bug can be found [here](https://lkml.org/lkml/2024/9/5/544).

The accompanying **blog post** can be found [here](https://binarygecko.com/blog).

### Notes
This vulnerability is ordinarily only exploitable on real hardware, due to software `PMU`s not supporting `aux` buffers.  
But because all major distributions mitigate the page corruption technique used in this PoC, you will either **crash** your system or see a lot of `bad page` entries in `dmesg` if you run it on your machine.

It is **recommended** to try this in a **virtual machine** with a **modified mainline kernel** that has been patched to enable `aux` buffers for software events.

### Quick Start
* have `qemu-system-x86_64` installed.  
* `make run`
* press up and run `/mnt/host/exploit` inside the VM.

### Structure
The `basic_linux_env` directory contains:
* `bzImage`: a build of a modified `6.9-rc1` kernel, as described in the `mainline.diff` file. You can replace this with your own kernel build.
* `initramfs`: a `busybox` based `initramfs` that mounts the `host` directory and has `/mnt/host/exploit` in the command history.
* `mainline.diff`: contains an example of how `aux` buffers can be enabled for software events.

The `Makefile` contains a `make run` command that assumes that you have `qemu-system-x86_64` installed.  
It will run `qemu` with the `bzImage` kernel and the `initramfs`.
