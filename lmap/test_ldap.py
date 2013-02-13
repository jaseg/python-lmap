#!/usr/bin/env python

from unittest import TestCase, main
from tempfile import NamedTemporaryFile, TemporaryDirectory
from subprocess import *
import sys,os
import ldap

# test slapd config
slapd_config = """
include   /etc/openldap/schema/core.schema
include   /etc/openldap/schema/cosine.schema
include   /etc/openldap/schema/inetorgperson.schema
include   /etc/openldap/schema/nis.schema

database ldif
suffix "ou=test,ou=pyldap,dc=jaseg,dc=de"
directory {dbdir}
rootdn "cn=root,ou=test,ou=pyldap,dc=jaseg,dc=de"
rootpw alpine
"""

ldap_objects = {
		# Test person
'uid=fnord,ou=test,ou=pyldap,dc=jaseg,dc=de': """
dn: uid=fnord,ou=test,ou=pyldap,dc=jaseg,dc=de
uid: fnord
uidNumber: 3737
gidNumber: 300
gecos: Frank Nord
cn: Frank Nord
sn: Nord
mail: fnord@example.physik.tu-berlin.de
homeDirectory: /home/f/fnord
loginShell: /usr/local/bin/zsh
description: A test user
objectClass: inetOrgPerson
objectClass: posixAccount
""",
# Test person
'uid=hacker,ou=test,ou=pyldap,dc=jaseg,dc=de': """
dn: uid=hacker,uid=hacker,ou=test,ou=pyldap,dc=jaseg,dc=de
uid: hacker
uidNumber: 3737
gidNumber: 300
gecos: Hans Acker
cn: Hans Acker
sn: Acker
mail: hacker@example.physik.tu-berlin.de
homeDirectory: /home/h/hacker
loginShell: /usr/local/bin/zsh
description: Another test user
objectClass: inetOrgPerson
objectClass: posixAccount
"""}

class slapdTest(TestCase):
	def setUp(self):
		# FIXME check this port number for availability
		self.port = 12454
		# create database directory
		self.database_dir = TemporaryDirectory()
		for name, content in ldap_objects.items():
			with open(self.database_dir.name + '/{}.ldif'.format(name), 'w') as f:
				f.write(content)
		# create temporary config file
		self.configfile = NamedTemporaryFile()
		self.configfile.write(bytes(slapd_config.format(dbdir=self.database_dir.name), 'UTF-8'))
		self.configfile.flush()

		uri = 'ldap://127.0.0.1:{}/'.format(self.port)
		self.slapd = Popen(['slapd', '-f', self.configfile.name, '-h', uri, '-d', '255'], stdout=PIPE, stderr=STDOUT)
		# wait for slapd to start
		for line in self.slapd.stdout:
			if 'slapd startup: initiated.' in str(line, 'UTF-8'):
				break
		print(str(self.slapd.stdout.readall(), 'UTF-8'))
		self.ldap = ldap.ldap(uri)

	def tearDown(self):
		self.slapd.kill()
		self.slapd.wait()
		print(str(self.slapd.stdout.readall(), 'UTF-8'))
		# the temporary files will be removed automatically

class TestSearch(slapdTest):
	def test_search(self):
		print(self.ldap('ou=test,ou=pyldap,dc=jaseg,dc=de'))

#class TestAdd(TestSearch):
#	pass

#class TestModify(TestSearch):
#	pass

#class TestDelete(TestSearch):
#	pass

if __name__ == '__main__':
	main()
