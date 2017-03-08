#!/bin/python

import os, time, smtplib, base64
from email import encoders
from email.mime.application import MIMEApplication
from email.MIMEMultipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase

sniff_file = 'sniff_data.txt'
cached_stamp = os.stat(sniff_file).st_mtime

from_addr = 'fw2 <root@fw2.beehosting.pro>'
to_addr = 'Juri <juri@itsupport.ee>'
body = 'Check attach for logs'
subject = 'Got scanned!'

while True:
	stamp = os.stat(sniff_file).st_mtime
	if stamp != cached_stamp:
	        cached_stamp = stamp
		msg = MIMEMultipart()
		msg['From'] = from_addr
		msg['To'] = to_addr
		msg['Subject'] = subject
		msg.attach(MIMEText(body))

		fp = open(sniff_file)
		att_msg = MIMEText(fp.read())
		att_msg.add_header('Content-Disposition', 'attachment', filename=sniff_file)
		msg.attach(att_msg)

		smtpObj = smtplib.SMTP('localhost')
		smtpObj.sendmail(from_addr, to_addr, msg.as_string())
	time.sleep(10)