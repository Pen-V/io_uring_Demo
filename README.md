## Cohort Uring call demo program
This program is a very naive demo program to show basic usability of uring push functionality

### Prerequisites
  - riscv64 cross compile toolchain
  - kernel patches for Cohort uring call

### How to build
Step 1. Apply custom kernel patches for cohort uring push by using `git apply`

Step 2. Compile kernel and emit linux headers into this repo
```
# Compile the kernel
make
# Emit new kernel headers
make headers_install [current io_uring_Demo directory]
```
I also have some small scripts in kernel source code to help 

Step 3. build demo program with `make all`

Step 4. Execute `a.out` on patched kernel

### How does it looks like(for now)
![image](https://github.com/user-attachments/assets/115b5371-80f4-4b42-8131-1ad9231fa83c)
