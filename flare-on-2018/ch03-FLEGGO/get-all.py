import re
import r2pipe
from subprocess import PIPE, run
from os import listdir
from os.path import isfile, join

def get_secret(f):
    r = r2pipe.open(f)
    key = r.cmd('psw @0x0040e0b0')
    return key

if __name__ == '__main__':
    mypath = './'
    onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]

    exe = re.compile('.*exe')
    for f in onlyfiles:
        if (exe.match(f)):
            key = get_secret(f)
            p = run(['wine',f], stdout=PIPE, input=bytes(key, 'ascii'))
            rex = re.compile('.*?(?P<info>\d+\.png\s=>\s.?).*', re.DOTALL)
            png, char = rex.match(p.stdout.decode('ascii')).group('info').split(' => ')
            print ('[+] file {}: key=>{}, png=>{}, char=>{}'.format(f,key,png,char))
