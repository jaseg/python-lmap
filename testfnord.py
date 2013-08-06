#!/usr/bin/env python3
from lmap import ldap
from getpass import getpass
import threading

pw = getpass()

def bind_fnord(num):
	def do_teh_action():
		ld = ldap.ldap('ldap://emmi.physik-pool.tu-berlin.de/')
		ld.simple_bind('uid=jaseg,ou=people,ou=pcpool,ou=physik,o=tu-berlin,c=de', pw)
		print(num, len(ld.search('ou=people,ou=pcpool,ou=physik,o=tu-berlin,c=de', filter='uid=jaseg')))
	return do_teh_action

for i in range(100):
	t = threading.Thread(target = bind_fnord(i))
	t.start()

