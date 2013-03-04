#!/usr/bin/env python

import sys,os,time
from test_ldap import BASE_DN, py_test_object
from unittest import TestCase, mock, main
from ldap import ldap, ldapmod
from lmap import lmap

class SlapdLmapTest(TestCase):
	def setUp(self):
		#super(self, SlapdLmapTest).setUp(self)
		self.ldap = mock.Mock(spec=ldap)
		res = py_test_object.copy()
		self.ldap.search.return_value = [(res['dn'], res)]
		self.lmap = lmap(py_test_object.copy(), BASE_DN, self.ldap)
	
	def testAdd(self):
		""" Add an object and see whether the data ends up in the database """
		attrs = py_test_object
		self.lmap.foo = lmap(attrs)
		self.lmap.commit()
		self.ldap.add.assert_called_with('ou=foo,'+BASE_DN, attrs)
	
	def testAttributeAdd(self):
		""" Add an attributes to an existing object via object[attribute] = value """
		self.lmap['test'] = 'foo'
		self.lmap.commit()
		self.ldap.modify.assert_called_with(BASE_DN, [(ldapmod.ADD, 'test', 'foo')])
		self.assertIn('test', self.lmap._cached_attrs)
		self.assertEqual(self.lmap._cached_attrs['test'], 'foo')

	def testAttributeReplace(self):
		""" Replace an attribute of an existing object via object[attribute] = value """
		self.lmap['uid'] = 'foobar'
		self.lmap.commit()
		self.ldap.modify.assert_called_with(BASE_DN, [(ldapmod.REPLACE, 'uid', 'foobar')])
		self.assertIn('uid', self.lmap._cached_attrs)
		self.assertEqual(self.lmap._cached_attrs['uid'], 'foobar')

	def testAttributeDelete(self):
		""" Delete an attribute of an existing object via object[attribute] = None """
		del self.lmap['uid']
		self.lmap.commit()
		self.ldap.modify.assert_called_with(BASE_DN, [(ldapmod.DELETE, 'uid', None)])
		self.assertNotIn('uid', self.lmap._cached_attrs)

	def testAttributeAccess(self):
		""" Test attribute access via object[attribute] """
		self.assertEqual(self.lmap['uid'], 'guest')
		self.assertNotIn('this_attrbite_should_not_exist', self.lmap)
		with self.assertRaises(KeyError):
			self.lmap['this_attribute_should_not_exist']

	def testTransactionLogic(self):
		""" Start a transaction, do some stuff and look whether the changes are recorded properly and whether the log is removed correctly on an error """
		with self.lmap as l:
			# add an attribute
			self.lmap['test'] = 'foo'
			self.assertIn('test', self.lmap)
			self.assertEqual(self.lmap['test'], 'foo')
			# replace an attribute
			self.lmap['uid'] = 'foobar'
			self.assertIn('uid', self.lmap)
			self.assertEqual(self.lmap['uid'], 'foobar')
			# remove an attribute
			del self.lmap['cn']
			self.assertNotIn('cn', self.lmap)
			with self.assertRaises(KeyError):
				self.lmap['cn']
		expected_mods = [(ldapmod.DELETE, 'cn', None), (ldapmod.REPLACE, 'uid', 'foobar'), (ldapmod.ADD, 'test', 'foo')]
		self.assertEqual(self.ldap.modify.call_args[0][0], BASE_DN)
		self.assertCountEqual(self.ldap.modify.call_args[0][1], expected_mods)
	
	def testDelete(self):
		""" Try deleting an object via parent.delete(childname) """
		attrs = py_test_object.copy()
		#This is tested above FIXME fully separate these two tests
		self.lmap.foo = lmap(attrs)
		self.lmap.foo._cached_children = {}
		del self.lmap.foo
		self.lmap.commit()
		self.ldap.delete.assert_called_with('ou=foo,'+BASE_DN)
		
if __name__ == '__main__':
	main()

