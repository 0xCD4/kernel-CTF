# Kernel CTF Challenges

A collection of Linux Kernel exploitation challenges for learning kernel security concepts.

## Requirements
- Linux system (tested on Ubuntu)
- Build essentials (gcc, make)
- Linux headers for your kernel version
```bash
sudo apt-get update
sudo apt-get install build-essential linux-headers-$(uname -r)
```

## Challenges

### Level 1: Basic Buffer Overflow
- Introduction to kernel module exploitation
- Simple buffer overflow vulnerability
- Good starting point for beginners
- Located in `/level1` directory

### Level 2: Use-After-Free
- More advanced kernel exploitation
- Use-After-Free vulnerability in a note-taking system
- Introduces kernel heap concepts
- Located in `/level2` directory

### Level 3: Race Condition
- Advanced kernel exploitation
- Multiple race conditions in a counter management system
- Focuses on parallel execution and timing attacks
- Located in `/level3` directory

## Getting Started
1. Clone this repository:
```bash
git clone https://github.com/0xCD4/kernel-CTF.git
cd kernel-CTF
```

2. Choose a challenge level and navigate to its directory:
```bash
cd level1  # or level2, level3
```

3. Follow the README.md in each challenge directory for specific instructions.

## Safety Notice
- These challenges are for educational purposes only
- Only run these modules in a testing environment
- Kernel exploits can crash your system - use a VM if possible

## Author
Created by shadowintel
