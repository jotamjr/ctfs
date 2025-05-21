#### Description

I've been learning more Windows API functions to do my bidding. Hmm... I swear this program was supposed to create a file and write the flag directly to the file. Can you try and intercept the file writing function to see what went wrong?Download the exe [here](https://challenge-files.picoctf.net/c_verbal_sleep/4aee1b9778a8e56724d015b027431fb236853a94f53e5dcf32c5ed32aed404da/bininst2.zip). Unzip the archive with the password `picoctf`

# Solution

Dumped the final payload similar to [[Binary Instrumentation 1]] and searched for strings, gladly it was in plain text (again) ...

![[Pasted image 20250310212915.png]]

BTW, this confirms that my previos thoughts on these challenges, this is not the intended solution.

After decoding the Base64 string we get the flag ...

```txt
picoCTF{fr1da_f0r_b1n_in5trum3nt4tion!_[redacted]}
```
