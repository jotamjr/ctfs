# Description

The imposter was able to fool us last time, so we've strengthened our defenses!Here's our [list](https://challenge-files.picoctf.net/c_verbal_sleep/aa9d13321037ee6659b6d49ddd19ee554ebdf685af5c369d982a2153c1a65123/cheese_list.txt) of cheeses.Connect to the program on our server: `nc verbal-sleep.picoctf.net 51325`

# Solution

```

*******************************************
***             Part 2                  ***
***    The Mystery of the CLONED RAT    ***
*******************************************

DRAT! The evil Dr. Lacktoes Inn Tolerant's clone was able to guess the cheese last time! I guess simple ciphers aren't good hashing methods. But now I've strengthened my encryption scheme so that now ONLY SQUEEXY can guess it...

Here's my secret cheese -- if you're Squeexy, you'll be able to guess it:  2dbbd0521e011285ff3ff7930258e35efdca7fa7ed8ead923ffe385b689b6066

Commands: (g)uess my cheese
What would you like to do?
```

Did several rounds and all of them came back with a 64 bytes hash, that sounds like sha-256, now we just need to hash all the chesses and append a salt to them.

After failing to get a matching hash bounced some ideas with a team mate and that's when the suggestion to get lower and upper case hashes came up ... hold and behold that worked, they were converting everything to lowercase before the hash :/

```

g

   _   _
  (q\_/p)
   /. .\.-.....-.     ___,
  =\_t_/=     /  `\  (
    )\ ))__ __\   |___)
   (/-(/`  `nn---'

SQUEAK SQUEAK SQUEAK

         _   _
        (q\_/p)
         /. .\
  ,__   =\_t_/=
     )   /   \
    (   ((   ))
     \  /\) (/\
      `-\  Y  /
         nn^nn


Is that you, Squeexy? Are you ready to GUESS...MY...CHEEEEEEESE?
Remember, this is my encrypted cheese:  2dbbd0521e011285ff3ff7930258e35efdca7fa7ed8ead923ffe385b689b6066
So...what's my cheese?
cream cheese
Annnnd...what's my salt?
91

         _   _
        (q\_/p)
         /. .\         __
  ,__   =\_t_/=      .'o O'-.
     )   /   \      / O o_.-`|
    (   ((   ))    /O_.-'  O |
     \  /\) (/\    | o   o  o|
      `-\  Y  /    |o   o O.-`
         nn^nn     | O _.-'
                   '--`

munch...

         _   _
        (q\_/p)
         /. .\         __
  ,__   =\_t_/=      .'o O'-.
     )   /   \      / O o_.-`|
    (   ((   ))      ).-'  O |
     \  /\) (/\      )   o  o|
      `-\  Y  /    |o   o O.-`
         nn^nn     | O _.-'
                   '--`

munch...

         _   _
        (q\_/p)
         /. .\         __
  ,__   =\_t_/=      .'o O'-.
     )   /   \      / O o_.-`|
    (   ((   ))        )'  O |
     \  /\) (/\          )  o|
      `-\  Y  /         ) O.-`
         nn^nn        ) _.-'
                   '--`

MUNCH.............

YUM! MMMMmmmmMMMMmmmMMM!!! Yes...yesssss! That's my cheese!
Here's the password to the cloning room:  picoCTF{cHeEsY2[redacted]}
```
