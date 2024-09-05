#!/bin/sh
qemu-system-x86_64 \
    -m 4096\
    -smp 8\
    -kernel bzImage\
    -append 'console=ttyS0'\
    -initrd initramfs\
    -virtfs local,path=./host,mount_tag=host,security_model=passthrough,id=host\
    -nographic\
    -serial mon:stdio
    #-gdb tcp::1234
