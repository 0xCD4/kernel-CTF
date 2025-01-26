# Kernel Buffer Overflow Challenge - Level 1

## Challenge Description
This is a beginner-friendly kernel exploitation challenge that introduces the concept of buffer overflows in kernel space. The challenge involves exploiting a vulnerable kernel module to read a hidden flag.

## Setup Instructions
1. Build the kernel module:
```bash
make
```

2. Load the kernel module:
```bash
sudo insmod vuln_module.ko
```

## Challenge Details
- The vulnerable module creates a proc file at `/proc/vuln`
- The kernel module has a buffer of 32 bytes
- The module doesn't properly check buffer sizes when copying data
- Goal: Trigger a buffer overflow to read the hidden flag

## How to Solve
1. First, read the initial content of the proc file:
```bash
cat /proc/vuln
```
You'll see a message indicating that you need to exploit the module.

2. Understand the Vulnerability:
- The module has a fixed buffer size of 32 bytes
- The write operation doesn't properly validate input size
- Writing more than 32 bytes will trigger the overflow

3. Exploit the Vulnerability:
- Create a program that writes more than 32 bytes to `/proc/vuln`
- You can use a simple C program or even echo:
```bash
# Using echo
python3 -c 'print("A"*64)' > /proc/vuln

# Or compile and run the provided exploit.c:
gcc -o exploit exploit.c
./exploit
```

4. Read the Flag:
```bash
cat /proc/vuln
```
If successful, you'll see the flag!

## Learning Objectives
- Understanding basic kernel module structure
- Learning about buffer overflows in kernel space
- Practice with proc filesystem interaction
- Basic exploitation techniques

## Tips
- The module gives clear feedback when you trigger the overflow
- No need for complex payload - just write more than 32 bytes
- Check kernel logs (`dmesg`) for helpful debugging messages
- The exploit doesn't require precise buffer sizes - any write larger than 32 bytes will work

## Files
- `vuln_module.c`: The vulnerable kernel module
- `exploit.c`: Example exploit code
- `Makefile`: For building the module

## Author
Created by shadowintel

Good luck and happy hacking!
