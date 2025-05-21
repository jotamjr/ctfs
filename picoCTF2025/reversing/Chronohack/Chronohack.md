#### Description

Can you guess the exact token and unlock the hidden flag?Our school relies on tokens to authenticate students. Unfortunately, someone leaked an important [file for token generation](https://challenge-files.picoctf.net/c_verbal_sleep/7ae3cdbcc5ac8f841a488d91465c1255ff0538f9061a2bb222293ec840af981c/token_generator.py). Guess the token to get the flag.

Additional details will be available after launching your challenge instance.

# Solution

The idea behind this challenge is to attack a vulnerable random number generation, we can see that we are using the current time as the seed.

```Python
def get_random(length):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    random.seed(int(time.time() * 1000))  # seeding with current time 
    s = ""
    for i in range(length):
        s += random.choice(alphabet)
    return s
```

If we are able to guess the seed, we should be able to generate the exact string returned by the get_random function.

The following code should generate a few guesses using the current time and start looking backwards for valid seeds.

```Python
def hunt():
  #pause()
  n = 0
  alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  length = 20
  r.recvuntil(b'\nEnter your guess for the token (or exit):')
  ctime = int(time.time() * 1000)
  while n < 50:
    print("current time: ",ctime)
    random.seed(ctime)  # seeding with current time
    s = ""
    for i in range(length):
      s += random.choice(alphabet)
    print ("current otp", s)
    r.sendline(s)
    line = r.recvline()
    if b'Congratulations' in line:
      break
    r.recvuntil(b'\nEnter your guess for the token (or exit):')
    ctime -= 1
    n += 1
  r.interactive()
```

**Keep** in mind that latency can affect the delta between the remote server time used for the seed and the one you generate with the script ...

![[Pasted image 20250310165219.png]]