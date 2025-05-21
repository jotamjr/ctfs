# Description

We invented a new cypher that uses "quantum entanglement" to encode the flag. Do you have what it takes to decode it?Connect to the program with netcat:`$ nc verbal-sleep.picoctf.net 52453`The program's source code can be downloaded [here](https://challenge-files.picoctf.net/c_verbal_sleep/9ff389c89cc804572242d1e2adfeb6bf6a9f1c03cb94c65b30a27f272e24a63d/quantum_scrambler.py).

# Solution

The python code generated what it seemed garbage at first ...

![Pasted image 20250520194745.png](./attachments/Pasted%20image%2020250520194745.png)

After testing it locally  it seems there is logic to this madness, at the end the python script is packing a bunch of stuff between the Nth and Nth+1 chars, with this insight it's just a matter of programmatically recover what we are interested in ...

```python
def unscramble(L):
A = L
print(len(A))
s = ""
for i in (A):
first, last = i[0], i[-1]
#print(first)
try:
value = int(first, 16)
if((value > 0x20) & ( value < 0x7f)):
#print(chr(value))
s+=chr(value)
except:
print("first", first[0])
try:
value = int(last, 16)
if((value > 0x20) & ( value < 0x7f)):
#print(chr(value))
s+=chr(value)
except:
print("last",last[-1])
print(s)
```

A bit buggy but we can recover the flag ...

```txt
picoCTF{python_is_weird[redacted]}
```
