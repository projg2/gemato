# gemato: hash support
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import hashlib
import io

import gemato.exceptions


HASH_BUFFER_SIZE = 65536


class SizeHash(object):
	"""
	A cheap wrapper to count file size via hashlib-like interface.
	"""

	__slots__ = ['size']

	def __init__(self):
		self.size = 0

	def update(self, data):
		self.size += len(data)

	def hexdigest(self):
		return self.size


def get_hash_by_name(name):
	"""
	Get a hashlib-compatible hash object for hash named @name. Supports
	multiple backends.
	"""
	# special case hashes
	if name == '__size__':
		return SizeHash()

	# general hash support
	if name in hashlib.algorithms_available:
		return hashlib.new(name)

	# fallback support
	if name.startswith('sha3_'):
		try:
			import sha3
		except ImportError:
			pass
		else:
			try:
				return getattr(sha3, name)()
			except AttributeError:
				pass
	elif name.startswith('blake2'):
		try:
			import pyblake2
		except ImportError:
			pass
		else:
			try:
				return getattr(pyblake2, name)()
			except AttributeError:
				pass

	raise gemato.exceptions.UnsupportedHash(name)


def hash_file(f, hash_names):
	"""
	Hash the contents of file object @f using all hashes specified
	as @hash_names. Returns a dict of (hash_name -> hex value) mappings.
	"""
	hashes = {}
	for h in hash_names:
		hashes[h] = get_hash_by_name(h)
	for block in iter(lambda: f.read1(HASH_BUFFER_SIZE), b''):
		for h in hashes.values():
			h.update(block)
	return dict((k, h.hexdigest()) for k, h in hashes.items())


def hash_path(path, hash_names):
	"""
	Hash the contents of file at specified path @path using all hashes
	specified as @hash_names. Returns a dict of (hash_name -> hex value)
	mappings.
	"""
	with io.open(path, 'rb') as f:
		return hash_file(f, hash_names)


def hash_bytes(buf, hash_name):
	"""
	Hash the data in provided buffer @buf using the hash @hash_name.
	Returns the hex value.
	"""
	return hash_file(io.BytesIO(buf), (hash_name,))[hash_name]
