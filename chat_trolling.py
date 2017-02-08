#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
TODO: 
	[+] group dialog 2000000000 + id
	[-] club dailog -id
	[+] mode 0 single trolling
	[-] mode 1 multi trolling top 100 dialogs
'''
import sys
import json as j 
import time
import signal
import getopt
import getpass
import requests 
import datetime
from html.parser import HTMLParser

line = '-' * 69

class FormParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.url         = None
        self.denial_url  = None
        self.params      = {}
        self.method      = 'GET'
        self.in_form     = False
        self.in_denial   = False
        self.form_parsed = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == 'form':
            if self.in_form:
                raise RuntimeError('Nested form tags are not supported yet')
            else:
                self.in_form = True
        if not self.in_form:
            return

        attrs = dict((name.lower(), value) for name, value in attrs)

        if tag == 'form':
            self.url = attrs['action']
            if 'method' in attrs:
                self.method = attrs['method']
        elif tag == 'input' and 'type' in attrs and 'name' in attrs:
            if attrs['type'] in ['hidden', 'text', 'password']:
                self.params[attrs['name']] = attrs['value'] if 'value' in attrs else ''
        elif tag == 'input' and 'type' in attrs:
            if attrs['type'] == 'submit':
                self.params['submit_allow_access'] = True
        elif tag == 'div' and 'class' in attrs:
            if attrs['class'] == 'near_btn':
                self.in_denial = True
        elif tag == 'a' and 'href' in attrs and self.in_denial:
            self.denial_url = attrs['href']

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == 'form':
            if not self.in_form:
                raise RuntimeError('Unexpected end of <form>')
            self.form_parsed = True
            self.in_form = False
        elif tag == 'div' and self.in_denial:
            self.in_denial = False

class VKAuth(object):

    def __init__(self, permissions, app_id, api_v, email=None, pswd=None, two_factor_auth=False, security_code=None, auto_access=True):
        """
        @args:
            permissions: list of Strings with permissions to get from API
            app_id: (String) vk app id that one can get from vk.com
            api_v: (String) vk API version
        """

        self.session        = requests.Session()
        self.form_parser    = FormParser()
        self._user_id       = None
        self._access_token  = None
        self.response       = None

        self.permissions    = permissions
        self.api_v          = api_v
        self.app_id         = app_id
        self.two_factor_auth= two_factor_auth
        self.security_code  = security_code
        self.email          = email
        self.pswd           = pswd
        self.auto_access    = auto_access

        if security_code != None and two_factor_auth == False:
            raise RuntimeError('Security code provided for non-two-factor authorization')

    def auth(self):
        """
            1. Asks vk.com for app authentication for a user
            2. If user isn't logged in, asks for email and password
            3. Retreives access token and user id
        """
        api_auth_url = 'https://oauth.vk.com/authorize'
        app_id = self.app_id
        permissions = self.permissions
        redirect_uri = 'https://oauth.vk.com/blank.html'
        display = 'wap'
        api_version = self.api_v

        auth_url_template = '{0}?client_id={1}&scope={2}&redirect_uri={3}&display={4}&v={5}&response_type=token'
        auth_url = auth_url_template.format(api_auth_url, app_id, ','.join(permissions), redirect_uri, display, api_version)

        self.response = self.session.get(auth_url)

        #look for <form> element in response html and parse it
        if not self._parse_form():
            raise RuntimeError('No <form> element found. Please, check url address')
        else:
            # try to log in with email and password (stored or expected to be entered)
            while not self._log_in():
                pass;

            # handling two-factor authentication
            # expecting a security code to enter here
            if self.two_factor_auth:
                self._two_fact_auth()

            # allow vk to use this app and access self.permissions
            self._allow_access()

            # now get _access_token and _user_id
            self._get_params()

            # close current session
            self._close()

    def get_token(self):
        """
            @return value:
                None if _access_token == None
                (String) access_token that was retreived in self.auth() method
        """
        return self._access_token

    def get_user_id(self):
        """
            @return value:
                None if _user_id == None
                (String) _user_id that was retreived in self.auth() method
        """
        return self._user_id

    def _parse_form(self):

        self.form_parser = FormParser()
        parser = self.form_parser

        try:
            parser.feed(str(self.response.content))
        except:
            print('Unexpected error occured while looking for <form> element')
            return False

        return True

    def _submit_form(self, *params):

        parser = self.form_parser

        if parser.method == 'post':
            payload = parser.params
            payload.update(*params)
            try:
                self.response = self.session.post(parser.url, data=payload)
            except requests.exceptions.RequestException as err:
                print("Error: ", err)
            except requests.exceptions.HTTPError as err:
                print("Error: ", err)
            except requests.exceptions.ConnectionError as err:
                print("Error: ConnectionError\n", err)
            except requests.exceptions.Timeout as err:
                print("Error: Timeout\n", err)
            except:
                print("Unexpecred error occured")

        else:
            self.response = None

    def _log_in(self):

        if self.email == None:
            self.email = ''
            while self.email.strip() == '':
                self.email = input('Enter an email to log in: ')

        if self.pswd == None:
            self.pswd = ''
            while self.pswd.strip() == '':
                self.pswd = getpass.getpass('Enter the password: ')

        self._submit_form({'email': self.email, 'pass': self.pswd})

        if not self._parse_form():
            raise RuntimeError('No <form> element found. Please, check url address')

        # if wrong email or password
        if 'pass' in self.form_parser.params:
            print('Wrong email or password')
            self.email = None
            self.pswd = None
            return False
        elif 'code' in self.form_parser.params and not self.two_factor_auth:
            self.two_factor_auth = True
        else:
            return True

    def _two_fact_auth(self):

        prefix = 'https://m.vk.com'

        if prefix not in self.form_parser.url:
            self.form_parser.url = prefix + self.form_parser.url

        if self.security_code == None:
            self.security_code = input('Enter security code for two-factor authentication: ')

        self._submit_form({'code': self.security_code})

        if not self._parse_form():
            raise RuntimeError('No <form> element found. Please, check url address')

    def _allow_access(self):

        parser = self.form_parser

        if 'submit_allow_access' in parser.params and 'grant_access' in parser.url:
            if not self.auto_access:
                answer = ''
                msg =   'Application needs access to the following details in your profile:\n' + \
                        str(self.permissions) + '\n' + \
                        'Allow it to use them? (yes or no)'

                attempts = 5
                while answer not in ['yes', 'no'] and attempts > 0:
                    answer = input(msg).lower().strip()
                    attempts-=1

                if answer == 'no' or attempts == 0:
                    self.form_parser.url = self.form_parser.denial_url
                    print('Access denied')

            self._submit_form({})

    def _get_params(self):

        try:
            params = self.response.url.split('#')[1].split('&')
            self._access_token = params[0].split('=')[1]
            self._user_id = params[2].split('=')[1]
        except IndexError as err:
            print('Coudln\'t fetch token and user id\n')
            print(err)

    def _close(self):
        self.session.close()
        self.response = None
        self.form_parser = None
        self.security_code = None
        self.email = None
        self.pswd = None

class VKAPI(object):
	url_type = 'https://api.vk.com/method/messages.setActivity'
	url_messages = 'https://api.vk.com/method/messages.get'
	url_user_info = 'https://api.vk.com/method/users.get'
	user_id = None
	access_token = None

	def __init__(self, email, password):
		self.email = email
		self.password = password
		vk = VKAuth(permissions=['messages'], app_id='3711461', api_v='5.52', email=self.email, pswd = self.password)
		try:
			vk.auth()
			self.access_token = vk.get_token()
			self.user_id = vk.get_user_id()
		except:
			print('auth error')

	def send_typing_status(self, peer_id):
		payload = {'user_id' : self.user_id, 'type' : 'typing',\
		           'access_token' : self.access_token,\
		           'v' : '5.52'}
		if peer_id - 2000000000 > 0:
			payload['peer_id'] = peer_id
		else:
			payload['user_id'] = peer_id
		r = requests.post(self.url_type, data=payload)
		return r.status_code == 200 and j.loads(r.text)['response'] == 1 

	def get_user_name(self, user_id):
		if len(user_id) > 0:
			payload = {'access_token' : self.access_token, 'v':'5.52','user_ids':str(user_id)[1:-1].replace(' ', '')}
			r = requests.post(self.url_user_info, data=payload)
			if r.status_code == 200:
				ret = {}
				for u in j.loads(r.text)['response']:
					ret[u['id']] = '{} {}'.format(u['first_name'], u['last_name'])
				return ret
			else:
				return None
		else:
			return None
			
	def get_user_chats(self, cnt=10):
		ret = {}
		offset, count = 0, 200
		while len(ret) < cnt:
			user_id_queue = []
			payload = {'offset':offset, 'count':count, 'access_token' : self.access_token, 'v':'5.52'}
			r = requests.post(self.url_messages, data=payload)
			if r.status_code == 200:
				arr = j.loads(r.text)['response']['items']
				if len(arr) > 0:
					for item in arr:
						if 'chat_id' in item:
							ret[2000000000 + item['chat_id']] = item['title']
						elif 'user_id' in item:
							if not (item['user_id'] in ret):
								user_id_queue.append(item['user_id'])
					res = self.get_user_name(user_id_queue)
					if res != None:
						ret = dict(ret.items() | res.items())
					else:
						return ret	
			else:
				return ret
			offset += 200
			time.sleep(0.05)
		return ret

def internet_on():
	sys.stdout.write('[*] checking internet connection')
	sys.stdout.flush()
	try:
		requests.get('https://google.com', timeout=(3, 3))
		sys.stdout.write('\r[+] checking internet connection\n')
		sys.stdout.flush()
		return True
	except: 
		return False

def print_table(table):
	col_width = [max(len(x) for x in col) for col in zip(*table)]
	for line in table:
		print('\t'+'-' * len('| ' + ' | '.join('{:{}}'.format(x, col_width[i]) for i, x in enumerate(line)) + ' | '))
		print('\t'+'| ' + ' | '.join('{:{}}'.format(x, col_width[i]) for i, x in enumerate(line)) + ' | ')
	print('\t'+'-' * len('| ' + ' | '.join('{:{}}'.format(x, col_width[i]) for i, x in enumerate(table[-1])) + ' | '))

def mode0(mail, password, n):
	header()
	if internet_on():
		v = VKAPI(email=mail, password=password)
		sys.stdout.write('[!] login as {0}({1})\n'.format(v.get_user_name([int(v.user_id)])[int(v.user_id)], v.user_id))
		sys.stdout.flush()
		result = v.get_user_chats(cnt=n)
		sys.stdout.write('[*] pull top {0} chats:\n'.format(len(result)))
		sys.stdout.flush()
		arr = [k for k,v in result.items()]
		table = [('{}.'.format(i+1), '{}({})'.format(result[arr[i]], arr[i])) for i in range(len(arr))]
		print_table(table)
		res = -1	
		while res < 0 or res > len(arr):
			res = int(input('  Choose target: '))
		cnt = 0
		t = 0
		print()
		while True:
			if v.send_typing_status(arr[res-1]):
				cnt += 1
				t = str(datetime.datetime.now())[11:]
			sys.stdout.write('\rtarget: {} requests: {} last success: {}'.format(result[arr[res-1]], cnt, t))
			sys.stdout.flush()
			time.sleep(5)
	else:
		sys.exit(-1)

def header():
	print('\n\tChatTrolling v2.0 implementation by @maxkrivich\n')
	print(line)

def parse_args(args):
	email, password = '', ''
	usage = '\nUsage:\n\tchat_prolling.py -e <email> -p <password>\n'
	if len(args) == 0:
		print(usage)
		sys.exit(-1)
	try:
		opts, args = getopt.getopt(args, 'he:p:',['help','email','password'])
	except getopt.GetoptError:
		print(usage)
		sys.exit(-1)
	for opt, arg in opts:
		if opt in ('-h','--help'):
			print(usage)
			sys.exit(0)
		elif opt in ('-e', '--email'):
			email = arg
		elif opt in ('-p', '--password'):
			password = arg
	if email != '' and password != '':
		return email, password 
	else:
		print(usage)
		sys.exit(-1)

def main(argv):
	email, password = parse_args(argv)
	mode0(mail=email, password=password, n=10)
	
def signal_handler(signal, frame):
	print('\r')
	print(line)
	sys.exit(0)	

if __name__ == '__main__':
	signal.signal(signal.SIGINT, signal_handler)
	main(sys.argv[1:])