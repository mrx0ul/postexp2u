#!/usr/bin/env python3

from pwn import *

ip = str(input("Enter target machine IP address: "))

if "l" in ip:
	ip = "localhost"

if "ubuntu" in ip:
	ip = "192.168.146.131"

port = input("Enter target machine port: ")

r = remote(ip.strip(), port.strip())

try:
	while True:

		while True:
			data = r.recv(1024, 0.000001)
			print(data.decode())
			if not data:
				break

		option = input()
		option = option.encode()
		if option != b'\n':
			r.sendline(option)
		else:
			print("Your input is empty!")

except KeyboardInterrupt:
	r.close()
	print("Connection terminated by keyboard interrupt.")