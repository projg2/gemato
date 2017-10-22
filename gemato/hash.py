# gemato: hash support
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import hashlib
import io


HASH_BUFFER_SIZE = 65536


class UnsupportedHash(Exception):
	def __init__(self, hash_name):
		super(UnsupportedHash, self).__init__(
				'Unsupported hash name: {}'.format(hash_name))


def get_hash_by_name(name):
	"""
	Get a hashlib-compatible hash object for hash named @name. Supports
	multiple backends.
	"""
	try:
		return hashlib.new(name)
	except ValueError:
		raise UnsupportedHash(name)


def hash_file(f, hash_names):
	"""
	Hash the contents of file object @f using all hashes specified
	as @hash_names. Returns a dict of (hash_name -> hex value) mappings.
	"""
	hashes = {}
	for h in hash_names:
		hashes[h] = get_hash_by_name(h)
	for block in iter(lambda: f.read(HASH_BUFFER_SIZE), b''):
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
