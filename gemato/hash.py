# gemato: hash support
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import hashlib
import io
try:
	import queue
except ImportError:
	import Queue as queue
import threading


HASH_BUFFER_SIZE = 65536


class UnsupportedHash(Exception):
	def __init__(self, hash_name):
		super(UnsupportedHash, self).__init__(
				'Unsupported hash name: {}'.format(hash_name))


class SizeHash(object):
	"""
	A cheap wrapper to count file size via hashlib-like interface.
	"""

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
	try:
		return hashlib.new(name)
	except ValueError:
		pass

	if name == '__size__':
		return SizeHash()

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

	raise UnsupportedHash(name)


def hash_one(hn, h, q, ret, retlock):
	while True:
		data = q.get()
		if data is not None:
			h.update(data)
		if data is None:
			break

	retlock.acquire()
	ret[hn] = h.hexdigest()
	retlock.release()


def hash_file(f, hash_names):
	"""
	Hash the contents of file object @f using all hashes specified
	as @hash_names. Returns a dict of (hash_name -> hex value) mappings.
	"""
	queues = []
	threads = []
	ret = {}
	retlock = threading.Lock()
	for hn in hash_names:
		h = get_hash_by_name(hn)
		q = queue.Queue(8)
		queues.append(q)
		threads.append(threading.Thread(target=hash_one,
			args=(hn, h, q, ret, retlock)))
	for t in threads:
		t.start()
	for block in iter(lambda: f.read(HASH_BUFFER_SIZE), b''):
		for q in queues:
			q.put(block)
	for q in queues:
		q.put(None)
	for t in threads:
		t.join()
	return ret


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
