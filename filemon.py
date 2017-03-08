#!/bin/python

import os, time, smtplib
from email.MIMEMultipart import MIMEMultipart
from email.mime.text import MIMEText

sniff_file = 'sniff_data.txt'
cached_stamp = os.stat(sniff_file).st_mtime

### vars to change

m_from = 'fw2 <root@honeypot.local.lan>'
m_to = 'Admin <admin@localhost.lan'
body = 'Check attach for logs'
subject = 'Got scanned!'

### /vars to change

while True:
	stamp = os.stat(sniff_file).st_mtime
	if stamp != cached_stamp:
	        cached_stamp = stamp
		msg = MIMEMultipart()
		msg['From'] = m_from
		msg['To'] = m_to
		msg['Subject'] = subject
		msg.attach(MIMEText(body))

		fp = open(sniff_file)
		att_msg = MIMEText(fp.read())
		att_msg.add_header('Content-Disposition', 'attachment', filename=sniff_file)
		msg.attach(att_msg)

		smtpObj = smtplib.SMTP('localhost')
		smtpObj.sendmail(m_from, m_to, msg.as_string())
	time.sleep(10)