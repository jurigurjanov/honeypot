#!/bin/python

import socket, select, smtplib, subprocess
subprocess.Popen(["python", "sniffer.py"])
subprocess.Popen(["python", "filemon.py"])

def server():
	import sys, os, socket

port_http = 80
port_smtps = 465
port_https = 443
port_ftp = 21
port_mysql = 3306
port_http_n = 8080
port_http_ns = 8443

m_from = 'fw2 <root@honeypot.local.lan>'
m_to = 'Admin <admin@localhost.lan'

sock_lst = []
host = ''
backlog = 5 # Number of clients on wait.
buf_size = 1024

try:
	for item in port_http, port_smtps, port_https, port_ftp, port_mysql, port_http_n, port_http_ns:
		sock_lst.append(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
		sock_lst[-1].setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		sock_lst[-1].bind((host, item))
		sock_lst[-1].listen(backlog)
except socket.error, (value, message):
	if sock_lst[-1]:
		sock_lst[-1].close()
		sock_lst = sock_lst[:-1]
	print 'Could not open socket: ' + message
	sys.exit(1)

while True:
	read, write, error = select.select(sock_lst,[],[])

	for r in read:
		for item in sock_lst:
			if r == item:
				accepted_socket, adress = item.accept()

				msg = """Subject: Hacked!

				New connection from to fw2!
				IP - """
				msg += " ".join(adress[0])
				smtpObj = smtplib.SMTP('localhost')
				smtpObj.sendmail(m_from, m_to, msg)
				data = accepted_socket.recv(buf_size)
				if data:
					print data
					accepted_socket.send('Hello, and goodbye.')
				accepted_socket.close()

server()