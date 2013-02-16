
import ldap, itertools

def _child_name(dn):
	return dn.partition(',')[0].partition('=')[2]

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
		self._rollback_state = None
		self._cached_attrs = attrs
		self._cached_children = None
	
#Transaction handling
	def __enter__(self):
		self.start_transaction()

	def __exit__(self, extype, exval, trace):
		if extype:
			self.rollback()
		else:
			self.commit()

	def start_transaction(self):
		self.fetch_attrs()
		self._rollback_state = self._cached_attrs.copy()

	def rollback(self):
		self._cached_attrs = self._rollback_state

	def commit(self):
		self._ldap.modify(self.dn, _compmod(self._cached_attrs, self._rollback_state)) #FIXME apparently, the ldap lib does not support timeouts here
		self._rollback_state = None
		#FIXME the following line seems sub-optimal and even unnecessary.
		self.fetch_attrs()
	
#Attribute access
	def fetch_attrs(self):
		_, self._cached_attrs = _, rv = self._ldap.search(self.dn, ldap.Scope.BASE, timeout=self.timeout)[0]
		return rv

	def keys(self):
		return self._cached_attrs or self.fetch_attrs()

	def __setitem__(self, name, value):
		#FIXME prevent self['dn'] and self.dn from getting out of sync?
		if not self._cached_attrs:
			self.fetch_attrs()
		if not self._rollback_state:
			op = ldap.ldapmod.ADD if name not in self._cached_attrs.keys() else ldap.ldapmod.REPLACE
			self._ldap.modify(self.dn, [(op, name, value)])
		self._cached_attrs[name] = value

	def __getitem__(self, name):
		if not self._cached_attrs:
			self.fetch_attrs()
		return self._cached_attrs[name]
	
	def __delitem__(self, name):
		if not self._cached_attrs:
			self.fetch_attrs()
		del self._cached_attrs[name]
		if not self._rollback_state:
			self._ldap.modify(self.dn, [(ldap.ldapmod.DELETE, name, None)])
	
	def __contains__(self, item):
		if not self._cached_attrs:
			self.fetch_attrs()
		return item in self._cached_attrs

	def __iter__(self):
		if not self._cached_attrs:
			self.fetch_attrs()
		return iter(self._cached_attrs)

	def __len__(self):
		if not self._cached_attrs:
			self.fetch_attrs()
		return len(self._cached_attrs)

	def __missing__(self, name):
		self.fetch_children()
		if name in self:
			return name
		raise KeyError(name+' not found')

	def __set__(self):
		pass #handle assignment of dicts as attrs

#Tree operations
	def add(self, rdn, entry):
		""" Add an entry under this entry with the given rdn """
		if _child_name(rdn) in self.children().keys():
			raise ValueError('There already is an entry at this position of the LDAP tree, or there is a naming collision.')
			#FIXME document these "naming collisions"
		if entry.dn:
			raise ValueError('The entry\'s dn is set, this means the entry already is part of an LDAP tree.')
		dn = '{},{}'.format(rdn, self.dn)
		entry.dn = dn
		entry._ldap = self._ldap
		self._ldap.add(dn, entry._cached_attrs)
		self._cached_children[_child_name(rdn)] = (dn, entry)

	def add_as(self, dn):
		""" Add this entry with the given absolute dn """
		if self.dn:
			raise ValueError('self.dn is set, this means this entry already is part of an LDAP tree.')
		self._ldap.add(dn, self._cached_attrs)

	def move(self, new_parent):
		self._ldap.move(self.dn, self.rdn, new_parent.dn)

	def fetch_children(self):
		self._cached_children = rv = { _child_name(dn): lmap(ldap=self._ldap, dn=dn, timeout=self.timeout) for dn, _ in self._ldap.search(self.dn, ldap.Scope.ONELEVEL, attrlist=[], timeout=self.timeout) }
		return rv

	def children(self):
		return self._cached_children if self._cached_children is not None else self.fetch_children()

	def __dir__(self):
		return list(itertools.chain(self.__dict__.keys(), iter(self.children())))
	
	def replace(self, childname, newchild):
		pass #FIXME

	#CAUTION: The behavior of this operation is a bit non-standard.
	def __setattr__(self, name, value):
		""" Add, delete or move an LDAP entry
			
			You may add a child LDAP entry by calling
				new_entry = lmap()
				existing_entry.new_child = new_entry
			You may move an LDAP entry by calling
				existing_entry.new_child = another_existing_entry
			Finally, you can recursively delete a child by calling
				existing_entry.existing_child = None
		"""
		if isinstance(value, lmap):
			if value is None: # Recursively delete child
				self.__delattr__(name)
			else: # Add or move entry
				if name in self.children().keys():
					raise KeyError('Child already exists: "{}"'.format(name))
				if value.dn: # Move entry
					value.move(self)
				else: # Add entry
					#FIXME really statically use ou here?
					self.add('ou='+name, value)
		self.__dict__[name] = value

	def __getattr__(self, name):
		if name == 'rdn':
			#FIXME is this correct?
			return self.dn.partition(',')[0]
		if name in self.children().keys():
			return self._cached_children[name]
		raise AttributeError(name)

	def delete(self, child):
		""" Delete a child """
		self.__delattr__(child)

	def __delattr__(self, name):
		""" Recursively delete an entry """
		if not self._cached_children:
			self.fetch_children()
		if not name in self._cached_children:
			raise AttributeError('Cannot delete {}: There is no such attribute in here!'.format(name))
		dn, child = self._cached_children[name]
		for name in child.children().keys():
			child.__delattr__(name)
		del self._cached_children[name]
		self._ldap.delete(dn)

	def __call__(self, *args):
		return [ lmap(ldap=self._ldap, dn=dn, timeout=timeout) for dn, _ in self._ldap.search_st(self.dn, ldap.Scope.SUBTREE, filter=args, attrlist=[], timeout=self.timeout).items() ]

#Auxiliary stuff
	def __str__(self):
		return "<'{}': {} with {}>".format(self.dn, str(self._cached_attrs), str(self.children()))

