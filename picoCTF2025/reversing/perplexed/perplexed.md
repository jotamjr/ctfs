# Description

Download the binary [here](https://challenge-files.picoctf.net/c_verbal_sleep/2326718ce11c5c89056a46fce49a5e46ab80e02d551d87744306ae43a4767e06/perplexed).

# Solution


There are just 2 functions that are interesting in this binary main and check ...

![Pasted image 20250520195444.png](./attachments/Pasted%20image%2020250520195444.png)

Reviewing the check function it seems that at offset 0x40117f we are moving some hard-coded values into some registers.
![Pasted image 20250520195601.png](./attachments/Pasted%20image%2020250520195601.png)

Probably this is an obfuscated/encoded form of our flag? Let's see how these values are pushed to the stack at the end ...

![Pasted image 20250310215700.png](./attachments/Pasted%20image%2020250310215700.png)

After reviewing the code I noticed that we were checking each bit to see if they matched, between the password and the "encoded" secret.

var_20 was incremented by 1 until it reached 8 and we started again.

![Pasted image 20250311195144.png](./attachments/Pasted%20image%2020250311195144.png)

With the shl (shift left), instructions it was creating values similar to.

```txt
10000000
01000000
00100000
... and so on 
```

A bitwise OR was applied to the stored value or the provided password.

![Pasted image 20250311195412.png](./attachments/Pasted%20image%2020250311195412.png)

So the TLDR is we are checking each bit and comparing if they match between the encoded secret and the provided password, the only caveat was that we were just checking 7 bits for the provided password vs 8 bits for the encoded secret and that started to create an offset after the first iteration as shown below.

```txt
letter p bit 1, cmp ffffffe1 bit 0: 40 > 1 80 > 1
letter p bit 2, cmp ffffffe1 bit 1: 20 > 1 40 > 1
letter p bit 3, cmp ffffffe1 bit 2: 10 > 1 20 > 1
letter p bit 4, cmp ffffffe1 bit 3: 0 > 0 0 > 0
letter p bit 5, cmp ffffffe1 bit 4: 0 > 0 0 > 0
letter p bit 6, cmp ffffffe1 bit 5: 0 > 0 0 > 0
letter p bit 7, cmp ffffffe1 bit 6: 0 > 0 0 > 0
letter i bit 1, cmp ffffffe1 bit 7: 40 > 1 1 > 1
letter i bit 2, cmp ffffffa7 bit 0: 20 > 1 80 > 1
letter i bit 3, cmp ffffffa7 bit 1: 0 > 0 0 > 0
letter i bit 4, cmp ffffffa7 bit 2: 8 > 1 20 > 1
letter i bit 5, cmp ffffffa7 bit 3: 0 > 0 0 > 0
letter i bit 6, cmp ffffffa7 bit 4: 0 > 0 0 > 0
letter i bit 7, cmp ffffffa7 bit 5: 1 > 1 4 > 1
letter c bit 1, cmp ffffffa7 bit 6: 40 > 1 2 > 1
letter c bit 2, cmp ffffffa7 bit 7: 20 > 1 1 > 1
letter c bit 3, cmp 1e bit 0: 0 > 0 0 > 0
letter c bit 4, cmp 1e bit 1: 0 > 0 0 > 0
letter c bit 5, cmp 1e bit 2: 0 > 0 0 > 0
letter c bit 6, cmp 1e bit 3: 2 > 1 10 > 1
letter c bit 7, cmp 1e bit 4: 1 > 1 8 > 1
```

At this point I took a shortcut and before reversing the whole thing I just printed the bit results for the encoded string, then I prefixed a 0 for each byte.

```txt
01110000
01101001
01100011
01101111
01000011
01010100
01000110
01111011
00110000
01101110
00110011
[truncated]
```

And after converting each byte to ASCII we got the flag ...

```txt
picoCTF{0n3_bi7_4t_a_[redacted]} 
```
