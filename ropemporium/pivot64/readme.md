# ROPemporium Pivot Write-up

The intro to this challenge reads

_"Stack space is at a premium in this challenge and you'll have to pivot the stack onto a second ROP chain elsewhere in memory to ensure your success."_

Reversing the binary was not the goal of this challenge, thus it was made pretty straightforward what it does. The binary first asks for input of length `0x100` bytes, which is stored on the heap. We are given address on the heap where this is stored. After that, the binary asks for additional `0x40` bytes of input, which are stored on the stack. This causes 0x18 bytes overflow and allows us to overwrite three quadwords on the stack and thus take control.

## Exploit Overview

Put together with the challenge description, it's clear we have to use the `0x18 bytes = 24 = 3*8 = 3 quadwords = 3 gadgets` overflow on stack by the second input to make the `rsp` point to malloc'd memory that contains our first input(our pivoted stack). Thus, our payload will consist of two parts:

1. up-to-three gadget chain that pivots the stack to the second part of our payload. The `malloc`'d address is given to us.
2. rop chain that runs `ret2win()` in `libpivot.so`.

_this can get a little bit confusing, since the binary first stores the second part of our payload to heap and only after that asks for the first part that is responsible for pivoting the stack._

## Exploit Construction

With initial exploit plan in our minds, let's have a look at the gadgets we have at our disposal, with `ropper`:
(_I only kept the important ones in this output_)
```
root@kali:~/ROPemporium/pivot# ropper -f pivot

[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%

Gadgets
=======

0x0000000000400b09: add rax, rbp; ret; 
...
0x000000000040098e: call rax; 
...
0x0000000000400b05: mov rax, qword ptr [rax]; ret; 
...
0x0000000000400b00: pop rax; ret; 
...
0x0000000000400900: pop rbp; ret; 
0x0000000000400b73: pop rdi; ret; 
...
0x0000000000400b02: xchg rax, rsp; ret; 
...

```

To pivot the stack, we need to know the address, where our second payload will be stored. This is, however, given to us by the binary for free. We will `recv()` and parse the standard output to retrieve the address of the `malloc`'d memory as `pivot_stack`.

Then, we send the second part of the payload, responsible for calling `ret2win` and after that the first part of the payload, which pivots to the second (main) part.

In order to call the `ret2win`, we need to know its address. We can do this, by reading the `got.plt` entry for `foothold_function`, to find where it is mapped in the process memory and adding the offset of `ret2win` - offset of `foothold_function` in `libpivot.so`. However, the `foothold_function` is not called during standard program execution and thus `got.plt` entry will only contain address back in `plt` section. To populate the `got.plt` entry of `foothold function`, we will `ret` to it at the beginning of the second part of our payload. After that, we can read the `got.plt` entry, add constant to it and make it point to `ret2win`. Please see the hijacked stacks for more explanations.

After we send the second part of the payload, the binary asks for another input, which actually overflows the stack with `0x18` bytes. This is where we send our pivoting payload.

This makes the hijacked stacks look as follows:

```
original stack overflown:
--------------------------------
|           pop rax             |
--------------------------------
|         pivot_stack           |---    - now rax contains the address of pivoted stack
--------------------------------    |
|         xchg rax, rsp         |   |
--------------------------------    |
                                    |
memory malloc'd for us:             |
-------------------------------- <--
|    plt.foothold_function      |
--------------------------------
|            pop rax            |
--------------------------------
|       got.foothold_function   | - now rax contains address of foothold_function's `got.plt` entry
--------------------------------
|   mov rax, qword ptr [rax]    | - now rax contains content of foothold_function's `got.plt` entry - address of foothold_function in proccess memory
--------------------------------
|           pop rbp             |
--------------------------------
|  ret2win - foothold_function  | - now rbp contains offset difference between ret2win and foothold_function
--------------------------------
|        add rax, rbp           | - now rax contains address of ret2win in process memory
--------------------------------
|           call rax            |
--------------------------------
```

For the original exploit refer to `exploit.py` file.

**Note:** To debug my rop chain, I used `radare2` with `rarun2` profile to make the binary listen on port `8080`. I then connected to this port with interactive python shell. This allowed me to construct and send my payloads on the fly.
