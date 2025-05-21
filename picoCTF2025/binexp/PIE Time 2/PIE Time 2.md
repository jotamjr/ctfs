# Description

Can you try to get the flag? I'm not revealing anything anymore!!Connect to the program with netcat:

```sh
$ nc rescued-float.picoctf.net 51030
```

The program's source code can be downloaded [here](https://challenge-files.picoctf.net/c_rescued_float/0ee50c4c94b334e2007d91218ac385470257261765b09a6620226865a05bf468/vuln.c). The binary can be downloaded [here](https://challenge-files.picoctf.net/c_rescued_float/0ee50c4c94b334e2007d91218ac385470257261765b09a6620226865a05bf468/vuln).

# Solution

This is an advanced variant of the first PIE Time challenge, on this one we need a leak in order to properly bypass ASLR.

Checking the binary we noticed that on the function **call_functions** we find a string format vulnerability, this allows us to leak pointers directly from memory (hopefully).

![Pasted image 20250307123123.png](./attachments/Pasted%20image%2020250307123123.png)

While debugging the binary and testing for results on different positions, we noticed that we get the return address leaked in position 19, this pointer matches the offset for main at offset 0x1441.

![Pasted image 20250330185220.png](./attachments/Pasted%20image%2020250330185220.png)

Armed with this information we can calculate the offset for the win function.

```
[+] Opening connection to rescued-float.picoctf.net on port 58146: Done
Enter your name: %19$p
0x5e167f006441

enter the address to jump to, ex => 0x12345: 0x5e167f00636a
You won!

picoCTF{p13_5h0u1dn'7_134k}
````

For a great introduction on format string vulnerabilities please check the [CS6265](https://tc.gts3.org/cs6265/2019/tut/tut05-fmtstr.html) infosec lab from Georgia Tech.
