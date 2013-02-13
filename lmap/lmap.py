
import ldap, itertools

class LMAP(dict):
#Object infrastructure
	def __init__(self, ldap=None, dn='', timeout=-1):
		self._ldap = ldap
		self.timeout = timeout
		self.dn = dn
		self._log = None
	
#Transaction handling
	def __enter__(self):
		self.start_transaction()

	def __exit__(self, extype, exval, trace):
		if extype:
			self.rollback()
		else:
			self.commit()

	def start_transaction(self):
		self.fetch()
		self._log = {}

	def rollback(self):
		self._log = None

	def commit(self):
		mod = lambda k,v: ldap.MOD_DELETE if v is None else (ldap.MOD_REPLACE if k in self._cached_attrs: else ldap.MOD_ADD)
		modlist = [ (mod(k,v), k, v) for k,v in self._log.items() ]
		self._ldap.modify(self.dn, modlist) #FIXME the ldap lib does not supports timeouts here
		self._log = None
	
#Attribute access
	def fetch_attrs(self):
		_, self._cached_attrs = _, rv = self._ldap.search(self.dn, ldap.SCOPE_BASE, timeout=self.timeout)[0]
		return rv

	def keys(self):
		return self._cached_attrs or self.fetch_attrs()

	def __setitem__(self, name, value):
		self._cached_attrs[name] = value

	def __getitem__(self, name):
		self._cached_attrs.__getitem__(name)

	def __missing__(self, name):
		self.fetch()
		if name in self:
			return name
		raise KeyError(name+' not found')

	def __set__(self):
		pass #handle assignment of dicts as attrs

#Tree operations
	def add(self, dn):
		""" Add this entry under the given dn """
		if self.dn:
			raise ValueError('self.dn is already set, this means this entry is already part of an LDAP tree. Please consider moving it instead.')
		self.dn = dn
		self._ldap.add(dn, self.attrs)

	def fetch_children(self):
		self._cached_children = rv = { self.child_name(dn): LMAP(self._con, dn, timeout) for dn, _ in self._ldap.search(self.dn, ldap.SCOPE_ONELEVEL, attrlist=[], timeout=self.timeout).items() }
		return rv

	def children(self):
		return self._cached_children or self.fetch_children()

	def __dir__(self):
		return list(itertools.chain(self.__dict__.keys(), iter(self.children())))
	
	#CAUTION: The behavior of this operation is a bit non-standard.
	def __setattr__(self, name, value):
		""" Add, delete or move an LDAP entry
			
			You may add a child LDAP entry by calling
				new_entry = LMAP()
				existing_entry.new_child = new_entry
			You may move an LDAP entry by calling
				existing_entry.new_child = another_existing_entry
			Finally, you can recursively delete a child by calling
				existing_entry.existing_child = None
		"""
		if isinstance(value, LMAP):
			if value is None: # Recursively delete child
				self.__delattr__(name)
			else: # Add or move entry
				if name in self.children().keys():
					raise KeyError('Child already exists: "{}"'.format(name))
				if value.dn: # Move entry
					value.move(self)
				else: # Add entry
					value.add( name + self.dn )
		self.__dict__[name] = value

	def __getattr__(self, name):
		if name in self.children().keys():
			return self._cached_children[name]
		raise AttributeError(name)

	def delete(self, child):
		""" Delete a child """
		self.__delattr__(child)

	def __delattr__(self, name):
		""" Recursively delete an entry """
		dn, child = self._cached_children[name]
		for name in child.children().keys():
			child.__delattr__(name)
		del self._cached_children[name]
		self._ldap.delete(dn)

	def __call__(self, *args):
		return [ LMAP(self._con, dn, timeout) for dn, _ in self._ldap.search_st(self.dn, ldap.SCOPE_SUBTREE, filter=*args, attrlist=[], timeout=self.timeout).items() ]

#Auxiliary stuff
	def __str__(self):
		return dn

