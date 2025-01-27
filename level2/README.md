# Kernel CTF Challenge - Level 2 (Use-After-Free)

## Challenge Description
This challenge introduces a Use-After-Free (UAF) vulnerability in kernel space. The module implements a simple note-taking system where notes can be created, freed, and read. The vulnerability allows reading and writing to freed memory locations.

## Vulnerability Details
- The module maintains an array of note structures
- Notes can be added, freed, and read
- When a note is freed, the pointer is not nulled out
- The freed memory can still be accessed
- Goal: Exploit the UAF to trigger the flag condition

## Setup Instructions
1. Build the kernel module:
```bash
make
```

2. Load the module:
```bash
sudo insmod vuln_module.ko
```

## Module Interface
The module creates a proc file at `/proc/vuln2` that accepts the following commands:

1. Add Note (A):
```
[A][content]
```

2. Free Note (F):
```
[F][note_id]
```

3. Read Note (R):
```
[R][note_id]
```

## Exploitation Steps
1. Create a note with some content
2. Free the note
3. Create a new note that will reuse the freed memory
4. Read the original note to trigger the UAF
5. The flag will be revealed when you successfully exploit the vulnerability

## Example Exploit
An example exploit is provided in `exploit.c`. To use it:
```bash
gcc -o exploit exploit.c
./exploit
```

## Learning Objectives
- Understanding Use-After-Free vulnerabilities
- Memory management in kernel space
- Kernel heap exploitation basics
- Dynamic memory allocation security

## Tips
- Pay attention to the order of operations
- Memory allocated with kmalloc() is not zeroed
- Freed memory can be reallocated by subsequent allocations
- Use dmesg to see kernel messages

## Files
- `vuln_module.c`: The vulnerable kernel module
- `exploit.c`: Example exploit code
- `Makefile`: For building the module

## Author
Created by 0xCD4

Good luck and happy hacking!
