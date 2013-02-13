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
dn: ou=test,ou=pyldap,o=jaseg,c=de
ou: test
objectClass: organizationalUnit
""",
# Test person
'ou=test,ou=pyldap,o=jaseg,c=de/uid=fnord.ldif': """# FOOBAR (this line actually *is* mission-critical. Please do not remove.)
dn: uid=fnord,ou=test,ou=pyldap,o=jaseg,c=de
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
""",
# Test person
'ou=test,ou=pyldap,o=jaseg,c=de/uid=hacker.ldif': """# FOOBAR (this line actually *is* mission-critical. Please do not remove.)
dn: uid=hacker,ou=test,ou=pyldap,o=jaseg,c=de
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
"""}

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
		self.ldap = ldap.ldap(uri)

	def tearDown(self):
		self.slapd.kill()
		self.slapd.wait()
		#print(str(self.slapd.stdout.readall(), 'UTF-8'))
		# the temporary files will be removed automatically

class TestSearch(SlapdTest):
	def test_search(self):
		self.ldap.simple_bind('cn=root,ou=test,ou=pyldap,o=jaseg,c=de', 'alpine')
		pprint.pprint(self.ldap('ou=test,ou=pyldap,o=jaseg,c=de'))

#class TestAdd(SlapdTest):
#	pass

#class TestModify(TestSearch):
#	pass

#class TestDelete(TestSearch):
#	pass

if __name__ == '__main__':
	main()
