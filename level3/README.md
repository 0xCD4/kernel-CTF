# Kernel CTF Challenge - Level 3 (Race Condition)

## Challenge Description
This challenge introduces a race condition vulnerability in a kernel module that manages named counters. The module has multiple race conditions in its counter management system, allowing for potential exploitation through parallel operations.

## Vulnerability Details
The module contains several race conditions:
1. Time-of-check to time-of-use (TOCTOU) in counter creation
2. Improper synchronization in counter increment operations
3. Race windows created by artificial delays

## Module Interface
The module creates a proc file at `/proc/vuln3` that accepts the following commands:

1. Create Counter (C):
```
[C][counter_name]
```

2. Increment Counter (I):
```
[I][counter_name]
```

3. Read Counter (R):
```
[R][counter_name]
```

4. Delete Counter (D):
```
[D][counter_name]
```

## Setup Instructions
1. Build the kernel module:
```bash
make
```

2. Load the module:
```bash
sudo insmod vuln_module.ko
```

## Exploitation Hints
1. The module contains intentional delays to make race conditions easier to hit
2. Multiple threads/processes can interact with the same counter simultaneously
3. The goal is to make a counter's value exceed 100
4. Consider:
   - Creating multiple instances of the same counter
   - Parallel increment operations
   - Timing between operations

## Learning Objectives
- Understanding race conditions in kernel space
- Time-of-check to time-of-use (TOCTOU) vulnerabilities
- Importance of proper synchronization
- Parallel execution exploitation

## Tips
- Use multiple threads or processes in your exploit
- Pay attention to the timing of operations
- Look for places where the code checks a condition and then uses it later
- Use `dmesg` to monitor the counter values and exploitation status

## Files
- `vuln_module.c`: The vulnerable kernel module
- `Makefile`: For building the module

## Author
Created by shadowintel

Good luck and happy hacking!
