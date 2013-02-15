#!/usr/bin/env python

from unittest import TestCase, main
from tempfile import NamedTemporaryFile, TemporaryDirectory
from subprocess import *
import sys,os,time
import os.path as path
import ldap
import pprint #FIXME debug stuff

# test slapd config
slapd_config = """
include         /etc/openldap/schema/core.schema
include         /etc/openldap/schema/cosine.schema
include         /etc/openldap/schema/nis.schema
include         /etc/openldap/schema/inetorgperson.schema

access to * by * write

backend         ldif
database        ldif
suffix			"ou=test,ou=pyldap,o=jaseg,c=de"
directory       "{dbdir}"
rootdn			"cn=root,ou=test,ou=pyldap,o=jaseg,c=de"
rootpw			"alpine"
"""

ldap_objects = {'ou=test,ou=pyldap,o=jaseg,c=de.ldif': """# FOOBAR (this line actually *is* mission-critical. Please do not remove.)
dn: ou=test
ou: test
objectClass: organizationalUnit
""",
# Test person
'ou=test,ou=pyldap,o=jaseg,c=de/uid=fnord.ldif': """# FOOBAR (this line actually *is* mission-critical. Please do not remove.)
dn: uid=fnord
uid: fnord
uidNumber: 3737
gidNumber: 300
gecos: Frank Nord
cn: Frank Nord
sn: Nord
mail: f.nord@example.physik.tu-berlin.de
homeDirectory: /home/f/fnord
loginShell: /usr/local/bin/zsh
description: A test user
objectClass: inetOrgPerson
objectClass: posixAccount
structuralObjectClass: inetOrgPerson
""",
# Test person
'ou=test,ou=pyldap,o=jaseg,c=de/uid=hacker.ldif': """# FOOBAR (this line actually *is* mission-critical. Please do not remove.)
dn: uid=hacker
uid: hacker
uidNumber: 2342
gidNumber: 300
gecos: Hans Acker
cn: Hans Acker
sn: Acker
mail: h.acker@example.physik.tu-berlin.de
homeDirectory: /home/h/hacker
loginShell: /usr/local/bin/zsh
description: Another test user
objectClass: inetOrgPerson
objectClass: posixAccount
structuralObjectClass: inetOrgPerson
"""}

py_test_object = {
	'dn': 'uid=guest,ou=test,ou=pyldap,o=jaseg,c=de',
	'uid': 'guest',
	'uidNumber': '1337',
	'gidNumber': '1000',
	'gecos': 'Eris Discordia',
	'cn': 'Eris Discordia',
	'sn': 'Discordia',
	'mail': 'ed@example.physik.tu-berlin.de',
	'homeDirectory': '/home/g/guest',
	'loginShell': '/usr/local/bin/zsh',
	'description': 'Test user',
	'objectClass': ['inetOrgPerson', 'posixAccount']}

class SlapdTest(TestCase):
	def setUp(self):
		# FIXME somehow check this port number for availability
		self.port = 12454
		# create database directory
		self.database_dir = TemporaryDirectory()
		dbdir = self.database_dir.name
		for relpath, content in ldap_objects.items():
			filepath, _ = path.split(relpath)
			cpath = path.join(dbdir, filepath)
			fpath = path.join(dbdir, relpath)
			if filepath and not path.exists(cpath):
				os.makedirs(cpath)
			with open(fpath, 'w') as f:
				f.write(content)
		# create temporary config file
		self.configfile = NamedTemporaryFile()
		self.configfile.write(bytes(slapd_config.format(dbdir=self.database_dir.name), 'UTF-8'))
		self.configfile.flush()

		uri = 'ldap://127.0.0.1:{}/'.format(self.port)
		self.slapd = Popen(['slapd', '-f', self.configfile.name, '-h', uri, '-d', 'none'], stdout=DEVNULL, stderr=DEVNULL)
		# FIXME give the server some time to start
		time.sleep(1)
		# connect and bind
		self.ldap = ldap.ldap(uri)
		self.ldap.simple_bind('cn=root,ou=test,ou=pyldap,o=jaseg,c=de', 'alpine')

	def tearDown(self):
		self.slapd.kill()
		self.slapd.wait()
		#print(str(self.slapd.stdout.readall(), 'UTF-8'))
		# the temporary files will be removed automatically

	def test_search(self):
		res = self.ldap('ou=test,ou=pyldap,o=jaseg,c=de')
		self.assertEqual(len(res), 3)
		for k, a, v in [('uid=fnord,ou=test,ou=pyldap,o=jaseg,c=de', 'uidNumber', ['3737']),
						('uid=hacker,ou=test,ou=pyldap,o=jaseg,c=de', 'uidNumber', ['2342']),
						('ou=test,ou=pyldap,o=jaseg,c=de', 'ou', ['test'])]:
			self.assertIn(k, res)
			self.assertIn(a, res[k])
			self.assertEqual(res[k][a], v)

	def test_add(self):
		self.ldap.add(py_test_object['dn'], py_test_object)
		with open(os.path.join(self.database_dir.name, 'ou=test,ou=pyldap,o=jaseg,c=de', 'uid=guest.ldif')) as f:
			db_lines = f.readlines()
			for k, vs in py_test_object.items():
				if k != 'dn':
					vs = vs if isinstance(vs, list) else [vs]
					for v in vs:
						self.assertIn('{}: {}\n'.format(k, v), db_lines)

	def test_delete(self):
		self.ldap.delete('uid=hacker,ou=test,ou=pyldap,o=jaseg,c=de')
		self.assertFalse(os.path.exists(os.path.join(self.database_dir.name, 'ou=test,ou=pyldap,o=jaseg,c=de', 'uid=hacker.ldif')))
	
	def test_modify(self):
		mods = [('uidNumber', ['9000']), ('description', ['Modified'])]
		self.ldap.modify('uid=fnord,ou=test,ou=pyldap,o=jaseg,c=de', [(ldap.ldapmod.REPLACE, k, v) for k, v in mods])
		with open(os.path.join(self.database_dir.name, 'ou=test,ou=pyldap,o=jaseg,c=de', 'uid=fnord.ldif')) as f:
			db_lines = f.readlines()
			for k, vs in mods:
				vs = vs if isinstance(vs, list) else [vs]
				for v in vs:
					self.assertIn('{}: {}\n'.format(k, v), db_lines)

if __name__ == '__main__':
	main()
