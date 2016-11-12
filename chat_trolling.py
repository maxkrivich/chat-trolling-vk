# -*- coding: utf-8 -*-

import requests
import time
import argparse
import sys
import json
import datetime
import urllib2
import atexit

'''
TODO: 
	[-] group dialog 2000000000 + id
	[-] club dailog -id
	[-] multi trolling top 100 dialogs
'''

URL = 'https://api.vk.com/method/messages.setActivity'
UID = None
PID = None
AT = None

line = '\n'+'='*69

def handler():
	print line
	end = time.time()
	elapsed = end-start
	print('end program {}'.format(elapsed))

def chek():
	global UID, PID, AT

	print('[*] checking parameters')

	if UID == None:
		print('user id is None')
		sys.exit()

	if PID == None:
		print('peer id is None')
		sys.exit()

	if AT == None:
		print('access token is None')
		sys.exit()

	if not internet_on():
		print('check you internet connection')
		sys.exit()

def internet_on():
	print('[*] checking internet connection')
	try:
		urllib2.urlopen('http://google.com', timeout=1)
		return True
	except urllib2.URLError as err: 
		return False

def parse():
	global UID, PID, AT
	parser = argparse.ArgumentParser()
	parser.add_argument('-u',action='store')
	parser.add_argument('-p', action='store')
	parser.add_argument('-t', action='store')
	arg = parser.parse_args()

	if arg.u:
		UID = arg.u
	if arg.p:
		PID = arg.p 
	if arg.t:
		AT = arg.t

def main():
	print('CHAT TROLLING v1.0 @maxkrivich\n')
	parse()
	chek()
	payload =	{
					'user_id': str(UID), 
					'type': 'typing', 
					'peer_id': str(PID), 
					'access_token': AT,
					'v': '5.60'
				}
	print line
	print str(datetime.datetime.now())[11:], '-', 'start working'
	req = 1
	while True:
		r = requests.post(URL, data=payload)
		if r.status_code == 200 and  json.loads(r.text)['response'] == 1:
			print('#{} uid: {} pid: {} time: {} status: {}'.\
					format(req ,UID, PID, str(datetime.datetime.now())[11:], r.status_code))
			req  += 1
		time.sleep(11)

if __name__ == '__main__':
	start = time.time()
	atexit.register(handler)
	main()
