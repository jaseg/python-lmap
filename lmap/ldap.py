
from ctypes import *

libldap = CDLL('libldap.so')
libldap.ldap_err2string.restype = c_char_p

# Helper stuff
def _make_c_array(values, type):
	if values:
		return ( type * len(values) )( *values )
	else:
		return ( c_void_p * 1 )()

def _make_c_attrs(attrs):
	""" Construct a C attribute list from a python attribute array """
	return _make_c_array( attrs, c_void_p ) + [ c_void_p() ] if attrs else None

def _make_c_modlist(mods):
	""" Construct a C modlist from a python mod tuple """
	return _make_c_array(
			[ ldapmod(
				mod_op = op,
				mod_type = bytes(type, 'ASCII'),
				mod_values = _make_c_array( [ bytes(v, 'ASCII') for v in values ], c_char_p )
				) for op, type, values in mods ],
			c_void_p ) + [ c_void_p() ]

def _libldap_call(func, errmsg, *args):
	ec = func(*args)
	if ec:
		raise LDAPError('{}: {}'.format(errmsg, str(libldap.ldap_err2string(ec), 'UTF-8')))
	return ec

def enum(**enums):
	return type('Enum', (), enums)

# C data structures and constants

# ldap.h
Scope = enum(BASE=0, ONELEVEL=1, SUBTREE=2, SUBORDINATE=3)
Option = enum(
		PROTOCOL_VERSION=0x11 )

# bits/time.h
class timeval(Structure):
	_fields_ = [('tv_sec', c_long), ('tv_usec', c_long)]

	def __init__(self, seconds=-1):
		""" Construct a timeval from a floating point number of seconds """
		seconds = seconds or -1
		super(Structure, self).__init__()
		self.tv_sec = int(seconds)
		self.tv_usec = int( ( seconds % 1 ) * 1000000 )

# ldap.h
class mod_vals_u(Union):
	_fields_ = [('strvals', POINTER(c_char_p)), ('bvals', POINTER(c_void_p))]

# ldap.h
class ldapmod(Structure):
	_fields_ = [('mod_op', c_int), ('mod_type', c_char_p), ('mod_vals', mod_vals_u)]
	ADD = 0
	DELETE = 1
	REPLACE = 2
	INCREMENT = 3 # OpenLDAP-specific

# lber.h
class berval(Structure):
	_fields_ = [('len', c_long), ('data', c_char_p)]

	def __init__(self, data):
		self.len = len(data)
		self.data = create_string_buffer(data)

class ldap:
	def __init__(self, uri):
		self._ld = c_void_p()
		_libldap_call(libldap.ldap_initialize, 'Cannot create LDAP connection', byref(self._ld), bytes(uri, 'ASCII'))
		version = c_int(3)
		_libldap_call(libldap.ldap_set_option, 'Cannot connect to server via LDAPv3.', self._ld, Option.PROTOCOL_VERSION, byref(version))
		pass #FIXME

	def __del__(self):
		self.close()

	def close(self):
		libldap.ldap_unbind_s(self._ld)

	def simple_bind(self, dn, pw):
		""" Bind using plain user/password authentication """
		_libldap_call(libldap.ldap_simple_bind_s, 'Cannot bind to server', self._ld, bytes(dn, 'ASCII'), bytes(pw, 'ASCII'))

	def complicated_bind(self, dn, cred, mechanism='GSSAPI'):
		""" Bind using SASL

		defaults to GSSAPI/Kerberos auth. cred should be a bytes object containing whatever your SASL mechanism requires.
		"""
		_libldap_call(libldap.ldap_sasl_bind_s, 'Cannot bind to server', self._ld, bytes(dn, 'ASCII'), bytes(mechanism, 'ASCII'), berval(cred), None, None, None)

	def add(self, dn, attrs):
		_libldap_call(libldap.ldap_add_s, 'Could not add something. For details, please consult your local fortuneteller.',  self._ld, bytes(dn, 'ASCII'), _make_c_modlist([ (ldapmod.ADD, key, value) for key, value in attrs ]) )

	def modify(self, dn, mods):
		_libldap_call(libldap.ldap_modify_s, 'Could not add something. For details, please consult your local fortuneteller.',  self._ld, bytes(dn, 'ASCII'), _make_c_modlist(mods) )

	def delete(self, dn):
		ec = libldap.ldap_delete( self._ld, bytes(dn, 'ASCII') )
		if ec:
			raise LDAPError('Could not add something. For details, please consult your local fortuneteller.')

	def __call__(self, base, **kwargs):
		return self.search(base, **kwargs)

	def search(self, base, scope=Scope.SUBTREE, filter=None, attrs=None, timeout=-1):
		""" Search the remove LDAP tree """
		results_pointer = c_void_p()
		#FIXME sizelimit value
		_libldap_call(libldap.ldap_search_ext_s, 'Search operation failed', self._ld, bytes(base, 'ASCII'), scope, filter, _make_c_attrs(attrs), 0, None, None, byref(timeval(timeout)), -1, byref(results_pointer))

		libldap.ldap_first_message.restype = c_void_p
		current_msg = libldap.ldap_first_message(self._ld, results_pointer)
		py_entries = []
		while current_msg:
			libldap.ldap_get_dn.restype = c_char_p
			py_dn = str(libldap.ldap_get_dn(self._ld, current_msg))
			py_attrs = []

			current_ber = c_void_p()
			libldap.ldap_first_attribute.restype = c_char_p
			current_attr = libldap.ldap_first_attribute(self._ld, current_msg, byval(current_ber))
			while current_attr:
				libldap.ldap_get_values.restype = POINTER(c_char_p)
				values = libldap.ldap_get_values(self._ld, current_msg, current_ber)
				py_values = []

				i = 0
				while values[i]:
					py_values.append(str(values[i]))
					i = i+1

				py_attrs.append( (str(current_attr), py_values) )

				libldap.ldap_value_free(values)

				libldap.ldap_next_attribute.restype = c_char_p
				next_attr = libldap.ldap_next_attribute(self._ld, current_msg, current_ber)
				libldap.ldap_memfree(current_attr)
				current_attr = next_attr
			ber_free(current_ber)

			py_entries.append( (py_dn, py_attrs) )

			libldap.ldap_next_message.restype = c_void_p
			next_msg = libldap.ldap_next_message(self._ld, current_msg)
			libldap.ldap_msgfree(current_msg)
			current_msg = next_msg

		return py_entries

class LDAPError(Exception):
	pass

