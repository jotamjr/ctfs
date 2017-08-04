# Reverse 100
This was the first challenge of the reversing challenges tree, we got a file called
files13.zip with a sha256 signature of 858a30f6ef4ce639dd5f0d79acc39865a349d02b14dafd18fc8770eab510a670.

After extracting this file we got a file called pocket:
```
 $ unzip files13.zip
 Archive:  files13.zip
  extracting: pocket
```
With the **file** tool we learned that this file is yet another zip file:
```
 $ file pocket
 pocket: Zip archive data, at least v2.0 to extract
```
We got another file and it seems that this time is a rar file:
```
 $ unzip pocket
 Archive:  pocket
   inflating: biscuit

 $ file biscuit 
 biscuit: RAR archive data, v4, os: Win32
```
Extracting this new file reveals two new files called biscuit1 and biscuit2:
```
 $ unrar x biscuit

 UNRAR 5.50 beta 4 freeware      Copyright (c) 1993-2017 Alexander Roshal


 Extracting from biscuit

 Extracting  biscuit1                                                  OK 
 Extracting  biscuit2                                                  OK 
 All OK
```
Taking a quick peek at both files:
```
 $ file biscuit1 
 biscuit1: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows

 $ file biscuit2 
 biscuit2: Zip archive data, at least v2.0 to extract
```
If we attempt to extract the biscuit2 file, a password prompt is shown:
```
 $ unzip biscuit2
 Archive:  biscuit2
 [biscuit2] biscuit4 password:
```
It seems that there is a secret hidden inside the biscuit1 executable that we need to discover first.

We started searching for strings (just in case) and found something intersting, the string:
**Please find sweets name starting from m for biscuit2.**
```
 vaddr=0x00405064 paddr=0x00003464 ordinal=005 sz=24 len=23 section=.rdata type=ascii string=Cannot allocate memory.
 vaddr=0x0040507c paddr=0x0000347c ordinal=006 sz=54 len=53 section=.rdata type=ascii string=Please find sweets name starting from m for biscuit2.
 vaddr=0x004050b2 paddr=0x000034b2 ordinal=007 sz=20 len=9 section=.rdata type=wide string=fedabnorm
```
This seems to be a hint for the zip password, we can try to bruteforce it but maybe just looking
deeper in the binary will reveal it.

Stepping through the binary we found the word macaron popping several times on the stack, after a quick
search it seems that indeed Macaron is a sweet from France :)
![macaron](/imgs/macaron.png)

We used macaron as our password to unzip the file biscuit2:
```
unzip biscuit2
Archive:  biscuit2
[biscuit2] biscuit4 password: 
  inflating: biscuit4
  inflating: biscuit5
  inflating: biscuit3
```
Nice, now we got three files:
```
file biscuit3 
biscuit3: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, comment: "Optimized by JPEGmini 3.13.3.15 0x411b5876", baseline, precision 8, 150x150, frames 3

file biscuit4
biscuit4: ASCII text, with CRLF line terminators

file biscuit5
biscuit5: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
```
We checked the txt file first (biscuit4):
```
cat biscuit4 
Please create flag.

hint:

Flag = TMCTF{biscuit3\_ biscuit5}
```
This seems to be a hint on how to create the flag using the other two files.

Lets take a look at biscuit3, opening that file with feh just show us a nice set of cookies so 
there is no hint in the image itself lets look at a binary level and find out what is in there, with 
binwalk we find something intersting:
```
 $ binwalk biscuit3
 DECIMAL       HEXADECIMAL     DESCRIPTION
 --------------------------------------------------------------------------------
 0             0x0             JPEG image data, JFIF standard 1.01
 382           0x17E           Copyright string: "Copyright (c) 1998 Hewlett-Packard Company"
 14253         0x37AD          Zip archive data, at least v1.0 to extract, compressed size: 5, uncompressed size: 5, name: biscuit.txt
 14356         0x3814          End of Zip archive
```
There seems to be a zip file within our image, lets use xxd to find out if we can extract something from 
the hex dump.

```
 $ xxd -s +0x37ad biscuit3 
 000037ad: 504b 0304 0a00 0000 0000 a776 714a 5fdc  PK.........vqJ\_.
 000037bd: 7fd8 0500 0000 0500 0000 0b00 0000 6269  ..............bi
 000037cd: 7363 7569 742e 7478 7463 7265 616d 504b  scuit.txtcreamPK
 000037dd: 0102 1400 0a00 0000 0000 a776 714a 5fdc  ...........vqJ\_.
 000037ed: 7fd8 0500 0000 0500 0000 0b00 0000 0000  ................
 000037fd: 0000 0100 2000 0000 0000 0000 6269 7363  .... .......bisc
 0000380d: 7569 742e 7478 7450 4b05 0600 0000 0001  uit.txtPK.......
 0000381d: 0001 0039 0000 002e 0000 0000 00         ...9.........
```

We can recover the zip file but its pretty safe to say that **cream** is our magic word here.

No lets check biscuit5:

After reversing this exectuable and stepping through its different functions we found that the
function @ 0x0040150b uses the substring biscu and does some char shifting with function @ 0x00401460,
the relevant asm code:
```
 0x004015ed      c74424080500.  mov dword [esp + local_8h], 5
 ...
 0x00401607      e8ac250000     call sym.\_strncpy
 ...
 0x00401656      e805feffff     call sym.\_shift_char
```
The functions copy 5 chars from the string biscuit and a loop using sym.\_shift_char transforms it to
**choux**.

![choux](/imgs/choux.png)

It seems that we have everything we need now, after sending our new flag TMCTF{cream\_ choux} it was not
accepted, after messing with the space and underscore we tried TMCTF{choux\_ cream} and that was the
flag that worked.
