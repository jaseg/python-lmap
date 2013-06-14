python-lmap
===========

This Python module contains two files: ```ldap.py``` and ```lmap.py```. ```ldap.py``` contains a *very* small Python 3.3-compatible openldap libldap-interface based on ctypes (that means it does not need any compiled code to work). This interface, though it *is* extremely simple, supports the most common LDAP operations.

```lmap.py``` is a (still *work in progress*) python object to LDAP mapper that supports all kinds of magic to make working with LDAP entries from python less of a pain. If you *are* going to use it, be careful because it might not (yet) behave as you would expect.

There are unit tests for both parts. In ```test_ldap.py``` you can find some code you may use to set up a temporary slapd (LDAP-server) for unit testing that will be automatically torn down after the tests.

Definition of "small"
---------------------

```
  181 lmap/ldap.py
  196 lmap/lmap.py
  377 total
          ***
  159 lmap/test_ldap.py
   81 lmap/test_lmap.py
  240 total
```

Performing SASL binds and ctypes problems
-----------------------------------------
The LDAP driver now supports SASL binds, for example for Kerberos. The default is to use kerberos via GSSAPI, using an existing ticket after you ran ```kinit```. You have to provide your Kerberos realm (this looks like a domain name).

Contributing
------------
If you like this code, fork it, send me a pull request ;)
