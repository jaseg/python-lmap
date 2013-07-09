#!/usr/bin/env python3
from lmap import ldap
from getpass import getpass
ld = ldap.ldap('ldaps://emmi.physik-pool.tu-berlin.de/')
pw = getpass()
ld.complicated_bind(user='uid=jaseg,ou=people,ou=pcpool,ou=physik,o=tu-berlin,c=de', password=pw)
#ld.complicated_bind(realm='', authcid='', password='')
print(ld.search('ou=people,ou=pcpool,ou=physik,o=tu-berlin,c=de', filter='uid=*ja*'))
