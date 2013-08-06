
import itertools
from lmap import ldap

# do a diff between two dicts and output the results as a modlist
def _compmod(new, old):
	modlist = []
	for k in new.keys():
		if k not in old:
			#print('+', k, new[k])
			modlist.append((ldap.ldapmod.ADD, k, new[k]))
		elif new[k] != old[k]:
			#print('=', k, new[k])
			modlist.append((ldap.ldapmod.REPLACE, k, new[k]))
	for k in old.keys():
		if k not in new:
			#print('-', k)
			modlist.append((ldap.ldapmod.DELETE, k, None))
	return modlist

class lmap(dict):
#Object infrastructure
	def __init__(self, attrs={}, dn='', ldap=None, timeout=-1):
		self._ldap = ldap
		self.timeout = timeout
		self.dn = dn
		self._rollback_state = {}
		if attrs:
			self.attrs = attrs
	
#Transaction handling
	def __enter__(self):
		self.start_transaction()

	def __exit__(self, extype, exval, trace):
		if extype:
			self.rollback()
		else:
			self.commit()

	def start_transaction(self):
		self._rollback_state = self.attrs.copy()

	def rollback(self):
		self.attrs = self._rollback_state

	def commit(self):
		#FIXME apparently, the ldap lib does not support timeouts here
		modlist = _compmod(self.attrs, self._rollback_state)
		if modlist and self._ldap and self.dn:
			self._ldap.modify(self.dn, modlist)
		self._rollback_state = self.attrs.copy()
	
#Attribute access
	def fetch_attrs(self):
		try:
			return list(self._ldap.search(self.dn, ldap.Scope.BASE, timeout=self.timeout).values())[0]
		except ldap.LDAPError:
			return {}
	
	def __setitem__(self, name, value):
		#FIXME prevent self['dn'] and self.dn from getting out of sync?
		self.attrs[name] = value

	def __getitem__(self, name):
		attr = self.attrs[name]
		if isinstance(attr, list) and len(attr) == 1:
			return attr[0]
		return attr
	
	def __delitem__(self, name):
		del self.attrs[name]
	
	def __contains__(self, item):
		return item in self.attrs

	def __iter__(self):
		return iter(self.attrs)

	def __len__(self):
		return len(self.attrs)

	def get(self, key, default=None):
		if key in self and self[key]:
			return self[key]
		return default

#Tree operations
	def has_child(self, rdn):
		return bool(self._ldap.search(self.dn, filter=rdn))

	def add(self, rdn, entry):
		""" Add an entry under this entry with the given rdn """
		if self.has_child(rdn):
			raise ValueError('There already is an entry at this position of the LDAP tree.')
		entry._ldap = self._ldap
		dn = '{},{}'.format(rdn, self.dn)
		entry.add_as(dn)
		self.children[rdn] = entry

	def add_as(self, dn):
		""" Add this entry with the given absolute dn """
		if self.dn:
			raise ValueError('self.dn is set, this means this entry already is part of an LDAP tree.')
		self.dn = dn
		rdnk = dn.split('=')[0]
		self._ldap.add(dn, { k:v for k,v in self.attrs.items() if not k == rdnk })

	def move(self, new_parent):
		self._ldap.move(self.dn, self.rdn, new_parent.dn)

	def fetch_children(self):
		try:
			self.children = rv = { l.rdn: l for l in [ lmap(ldap=self._ldap, dn=dn, timeout=self.timeout) for dn in self._ldap.search(self.dn, ldap.Scope.ONELEVEL, attrs=[], timeout=self.timeout).keys() ] }
		except ldap.LDAPError:
			self.children = rv = {}
		return rv

	def __dir__(self):
		return list(itertools.chain(self.__dict__.keys(), iter(self.children)))
	
	def replace(self, childname, newchild):
		pass #FIXME

	#CAUTION: The behavior of this operation is a bit non-standard.
	#...on the other hand, I think this whole thing can be considered non-standard...
	def __setattr__(self, name, value):
		if isinstance(value, str) and name != 'dn':
			self.attrs[name] = value
		self.__dict__[name] = value

	def __getattr__(self, name):
		if name == 'rdn':
			return self.dn.split(',')[0]
		if name == 'attrs':
			rv = self.attrs = self.fetch_attrs()
			self.start_transaction()
			return rv
		if name == 'children':
			return self.fetch_children()
		if name in self:
			return self[name]
		raise AttributeError(name)

	def delete(self):
		for child in self.children.values():
			child.delete()
		self._ldap.delete(dn)

	def __call__(self, rdn):
		childdn = rdn+','+self.dn
		child = lmap(ldap=self._ldap, dn=childdn, timeout=self.timeout)
		self.children[rdn] = child
		return child
	
	def search(self, filter, subtree=True):
		return [ lmap(ldap=self._ldap, dn=dn, attrs=attrs, timeout=self.timeout) for dn, attrs in self._ldap.search(self.dn, ldap.Scope.SUBTREE if subtree else ldap.Scope.ONELEVEL, filter=filter, attrs=[], timeout=self.timeout).items() ]

#Auxiliary stuff
	def __str__(self):
		return "<'{}': {} with {}>".format(self.dn, str(self.attrs), str(self.children))

