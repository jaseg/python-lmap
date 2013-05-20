
import itertools
from lmap import ldap

# do a diff between two dicts and output the results as a modlist
def _compmod(new, old):
	modlist = []
	for k in new.keys():
		if k not in old:
			modlist.append((ldap.ldapmod.ADD, k, new[k]))
		elif new[k] != old[k]:
			modlist.append((ldap.ldapmod.REPLACE, k, new[k]))
	for k in old.keys():
		if k not in new:
			modlist.append((ldap.ldapmod.DELETE, k, None))
	return modlist

class lmap(dict):
#Object infrastructure
	def __init__(self, attrs=None, dn='', ldap=None, timeout=-1):
		self._ldap = ldap
		self.timeout = timeout
		self.dn = dn
		self._rollback_state = {}
	
	def __del__(self):
		self.commit()

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
		self._ldap.modify(self.dn, _compmod(self.attrs, self._rollback_state))
		self._rollback_state = self.attrs.copy()
	
#Attribute access
	def fetch_attrs(self):
		return self._ldap.search(self.dn, ldap.Scope.BASE, timeout=self.timeout)[0][1]
	
	def __setitem__(self, name, value):
		#FIXME prevent self['dn'] and self.dn from getting out of sync?
		self.attrs[name] = value

	def __getitem__(self, name):
		return self.attrs[name]
	
	def __delitem__(self, name):
		del self.attrs[name]
	
	def __contains__(self, item):
		return item in self.attrs

	def __iter__(self):
		return iter(self.attrs)

	def __len__(self):
		return len(self.attrs)

#Tree operations
	def add(self, rdn, entry):
		""" Add an entry under this entry with the given rdn """
		if rdn in self.children.keys():
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
		self._ldap.add(dn, self.attrs)

	def move(self, new_parent):
		self._ldap.move(self.dn, self.rdn, new_parent.dn)

	def fetch_children(self):
		self.children = rv = { l.rdn: l for l in [ lmap(ldap=self._ldap, dn=dn, timeout=self.timeout) for dn, _ in self._ldap.search(self.dn, ldap.Scope.ONELEVEL, attrlist=[], timeout=self.timeout) ] }
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
			pass #FIXME
		if name == 'attrs':
			rv = self.attrs = self._rollback_state = self.fetch_attrs()
			return rv
		if name == 'children':
			return fetch_children()
		if name in self.attrs.keys():
			return self.attrs[name]
		raise AttributeError(name)

	def delete(self):
		for child in self.children.values():
			child.delete()
		self._ldap.delete(dn)

	def __call__(self, rdn):
		return self.children[rdn]
	
	def search(self, *args):
		return [ lmap(ldap=self._ldap, dn=dn, timeout=timeout) for dn, _ in self._ldap.search_st(self.dn, ldap.Scope.SUBTREE, filter=args, attrlist=[], timeout=self.timeout).items() ]

#Auxiliary stuff
	def __str__(self):
		return "<'{}': {} with {}>".format(self.dn, str(self.attrs), str(self.children))

