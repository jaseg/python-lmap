
from ctypes import *
import time

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
	return _make_c_array( [cast(c_char_p(bytes(attr, 'UTF-8')), c_void_p) for
						   attr in attrs] + [c_void_p()], c_void_p ) if attrs else None

def _libldap_call(func, errmsg, *args):
	#print('libldap call:', func, *args)
	ec = func(*args)
	if ec:
		raise LDAPError('{}: {}'.format(errmsg, str(libldap.ldap_err2string(ec), 'UTF-8')))
	return ec

def _bytes_or_none(s):
	return None if s is None else bytes(s, 'UTF-8')

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

	@classmethod
	def modlist(cls, mods):
		""" Construct a C modlist from a python mod tuple """
		py_array = []
		for op, type, values in mods:
			if not isinstance(values, list):
				if values == None:
					values = ''
				values = [values]
			if op == ldapmod.DELETE:
				values = []
			pyvals = [ c_char_p(bytes(v, 'UTF-8')) for v in values ] + [ cast(c_void_p(), c_char_p) ]
			#print('MOD ', op, type, pyvals)
			mod = ldapmod(mod_op = op,
					mod_type = bytes(type, 'UTF-8'),
					mod_vals = mod_vals_u(strvals=_make_c_array(pyvals, c_char_p)))
			py_array.append(pointer(mod))
		py_array.append(cast(0, POINTER(ldapmod)))
		return _make_c_array(py_array, POINTER(ldapmod))

# lber.h
class berval(Structure):
	_fields_ = [('len', c_long), ('data', c_char_p)]

	def __init__(self, data):
		if data is None:
			self.len = 0
			self.data = c_char_p()
		else:
			self.len = len(data)
			self.data = c_char_p(data)

# ldap.h 
LDAP_OTHER				= 0x50
LDAP_SASL_INTERACTIVE	= 1
LDAP_SASL_QUIET			= 2

# sasl.h
class interact_type(Structure):
	_fields_ = [('id', c_long), ('challenge', c_char_p), ('prompt', c_char_p), ('defresult', c_char_p), ('result', c_char_p), ('len', c_int)]

INTERACTION_FUNCTION = CFUNCTYPE(c_int, c_void_p, c_int, c_void_p, POINTER(interact_type))
def bind_sasl_interact(defaults):
	def sasl_interact(ld, flags, cdefaults, ilist):
		print('INTERACTING WITH SASL')
		i=0
		while ilist[i].id:
			ia = ilist[i].id
			if ia not in defaults:
				print('ID NOT FOUND IN DEFAULTS')
				return LDAP_OTHER # Not sure if this is necessary
			print('ID', ilist[i].id, 'REQUESTED, ANSWER', defaults[ia])
			ilist[i].result = _bytes_or_none(defaults[ia])
			ilist[i].len = len(defaults[ia]) if defaults[ia] else 0
			i = i+1
		print('NO MORE PROMPTS')
		return 0 # LDAP_SUCCESS
	return sasl_interact

class SaslInteractionIds:
	USERNAME	= 0x4001
	AUTHNAME	= 0x4002
	PASSWORD	= 0x4004
	GETREALM	= 0x4008


class ldap:
	def __init__(self, uri):
		self._ld = c_void_p()
		_libldap_call(libldap.ldap_initialize, 'Cannot create LDAP connection', byref(self._ld),
												bytes(uri, 'UTF-8'))
		version = c_int(3)
		_libldap_call(libldap.ldap_set_option, 'Cannot connect to server via LDAPv3.',
												self._ld, Option.PROTOCOL_VERSION, byref(version))

	def close(self):
		libldap.ldap_unbind_s(self._ld)

	def simple_bind(self, dn, pw):
		""" Bind using plain user/password authentication """
		_libldap_call(libldap.ldap_simple_bind_s, 'Cannot bind to server', self._ld,
												   bytes(dn, 'UTF-8'), bytes(pw, 'UTF-8'))

	def complicated_bind(self, user='', password='', mech='GSSAPI', authzid='', realm=''):
		""" Bind using SASL

		Defaults to GSSAPI/Kerberos auth, but may be used with other SASL
		mechanisms.

		Call this without arguments to use an existing kerberos ticket from the
		user's ticket cache or give a user DN/password combination via the
		``user`` and ``password`` args. Please be careful to actually provide
		the full DN of the user's entry in the user field, *not* the kerberos
		uid or principal. Also, please note that the ``realm`` argument is not
		really used by libldap to contain anything resembling a kerberos realm.
		Just leave it empty unless you know what you are doing.

		Examples:
		ld = ldap('ldap://localhost/')
		ld.complicated_bind() # Use an existing kerberos ticket from the user's cache

		ld = ldap('ldap://localhost/')
		ld.complicated_bind(user='uid=fnord,cn=admins,cn=config', 'p@ssw0rd')
		"""
		defaults = {
			SaslInteractionIds.USERNAME: authzid,
			SaslInteractionIds.AUTHNAME: user,
			SaslInteractionIds.PASSWORD: password,
			SaslInteractionIds.GETREALM: realm
		}

		mech		= bytes(mech, 'UTF-8')
		# We are doing a little trick here. In C code, we would pass a defaults
		# structure of our liking to ldap_sasl_interactive_bind_s, which would
		# pass it to our interact callback in turn. This defaults structure
		# would then tell our interact callback what to do. Since we are
		# writing python code, we can just dynamically generate a callback from
		# a closure already containing the defaults, thereby just using python
		# and leaving the defaults pointer vacant.
		interact = INTERACTION_FUNCTION(bind_sasl_interact(defaults))
		# FIXME I am quite curous what the stack trace looks like when the
		# python callback called from libldap raises an error
		_libldap_call(libldap.ldap_sasl_interactive_bind_s, 'Cannot bind via SASL',
			self._ld,
			None,
			mech,
			None,
			None,
			0, #LDAP_SASL_QUIET,
			interact,
			byref(c_void_p())) # I think we need to at least provide *something* to libldap here. FIXME: check wheter this works with a null pointer.

	def add(self, dn, attrs):
		modlist = ldapmod.modlist([(ldapmod.ADD, key, value) for key, value in attrs.items() if key != 'dn'])
		_libldap_call(libldap.ldap_add_ext_s, 'Could not add something. For details, please consult your local fortuneteller',  self._ld, bytes(dn, 'UTF-8'), modlist, None, None )

	def modify(self, dn, mods):
		_libldap_call(libldap.ldap_modify_ext_s, 'Could not modify something. For details, please consult your local fortuneteller',  self._ld, bytes(dn, 'UTF-8'), ldapmod.modlist(mods), None, None)

	def move(self, dn, newrdn, parentdn):
		_libldap_call(libldap.ldap_rename_s, 'Could not move something. For details, please consult your local fortuneteller',  self._ld, bytes(dn, 'UTF-8'), bytes(newrdn, 'UTF-8'), bytes(parentdn, 'UTF-8'), True, None, None)

	def delete(self, dn):
		ec = libldap.ldap_delete_s(self._ld, bytes(dn, 'UTF-8'))
		if ec:
			raise LDAPError('Could not delete something. For details, please consult your local fortuneteller: {}'.format(str(libldap.ldap_err2string(ec), 'UTF-8')))

	def __call__(self, base, **kwargs):
		return self.search(base, **kwargs)

	def search(self, base, scope=Scope.SUBTREE, filter=None, attrs=None, timeout=-1):
		""" Search the remove LDAP tree """
		results_pointer = c_void_p()
		#FIXME sizelimit value
		_libldap_call(libldap.ldap_search_ext_s,
				'Search operation failed (base: "{}" filter: "{}")'.format(base, filter),
				self._ld,
				bytes(base, 'UTF-8'),
				scope,
				bytes(filter, 'UTF-8') if filter else None,
				_make_c_attrs(attrs),
				0,
				None,
				None,
				byref(timeval(timeout)),
				-1,
				byref(results_pointer))

		libldap.ldap_first_entry.restype = c_void_p
		current_msg = cast(libldap.ldap_first_entry(self._ld, results_pointer), c_void_p)
		py_entries = {}
		while current_msg:
			libldap.ldap_get_dn.restype = c_char_p
			c_dn = libldap.ldap_get_dn(self._ld, current_msg)
			py_dn = str(c_dn, 'UTF-8')
			#print('HANDLING ENTRY {}'.format(py_dn))
			#print('freeing dn')
			#libldap.ldap_memfree(c_dn) FIXME complains that the pointer points to an invalid memory area
			py_attrs = {}

			current_ber = c_void_p()
			libldap.ldap_first_attribute.restype = c_char_p
			current_attr = libldap.ldap_first_attribute(self._ld, current_msg, byref(current_ber))
			while current_attr:
				libldap.ldap_get_values.restype = POINTER(c_char_p)
				values = libldap.ldap_get_values(self._ld, current_msg, current_attr)

				attr_name = str(current_attr, 'UTF-8')
				py_values = py_attrs.get(attr_name, [])

				if values:
					i = 0
					while values[i]:
						py_values.append(str(values[i], 'UTF-8'))
						i = i+1

				py_attrs[attr_name] = py_values

				libldap.ldap_value_free(values)

				#print('freeing current attribute')
				#libldap.ldap_memfree(current_attr) FIXME makes some assert() fail
				libldap.ldap_next_attribute.restype = c_char_p
				next_attr = libldap.ldap_next_attribute(self._ld, current_msg, current_ber)
				current_attr = next_attr
			libldap.ber_free(current_ber)

			py_entries[py_dn] = py_attrs

			libldap.ldap_next_entry.restype = c_void_p
			next_msg = cast(libldap.ldap_next_entry(self._ld, current_msg), c_void_p)
			current_msg = next_msg

		#print('freeing message')
		#libldap.ldap_msgfree(results_pointer) FIXME segfaults
		return py_entries

class LDAPError(Exception):
	pass

