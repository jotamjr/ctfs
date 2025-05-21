#### Description

I have been learning to use the Windows API to do cool stuff! Can you wake up my program to get the flag?Download the exe [here](https://challenge-files.picoctf.net/c_verbal_sleep/c71239e2890bd0008ff9c1da986438d276e7a96ba123cb3bc7b04d5a3de27fe7/bininst1.zip). Unzip the archive with the password `picoctf`

# Solution

With the help of tools like pestudio and DIE we get some idea that the binary is packed, based on section 6 name.
![[Pasted image 20250309103852.png]]

And the original name of the export ...

![[Pasted image 20250309103926.png]]

It seems we are dealing with [AtomPePacker](https://github.com/NUL0x4C/AtomPePacker), 

Once we start exploring our entrypoint at 0x1bf0, we see some interesting stuff like the check of the OsMajorVersion, probably as an anti-reversing checks.

![[Pasted image 20250309134340.png]]

Continuing our reversing, it seems that at offset +0x1dc0 there are a few checks to confirm the extraction of a binary, searching for the header MZ (bytes 5A4D), PE and then looking for the .text section and so on.

![[Pasted image 20250309194253.png]]

Se we are sure that we are dealing with a PE file in the pointer at RCX, this seems to be the unpacked form of the final binary. We dump that to a binary file and look for strings.

![[Pasted image 20250309194849.png]]

This is a base64 encoded strings that translates to:

```
picoCTF{w4ke_m3_up_w1th_fr1da_[redacted]}
```

There word frida in the flag makes me think this was not an intended solution but we'll count it as a victory.
