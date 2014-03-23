#!/usr/bin/python


def _safeascii(x):
	o = ord(x)
	if o >= 32 and o < 127:
		return x
	else:
		return '.'


def _hex_some_chars(line):
	for i in range(len(line)):
		yield "{0:02x}".format(ord(line[i]))


def hexdump(data):
	ret = []
	for i in range(0, len(data), 16):
		line = data[i:i + 16]
		half1 = " ".join(_hex_some_chars(line[:8]))
		half2 = " ".join(_hex_some_chars(line[8:]))
		ret.append("{0:08x}: {1:23s}  {2:23s}  {3:s}".format(
			i, half1, half2, "".join(map(_safeascii, line))
		))
	return "\n".join(ret)

class RODict(dict):
	"""Like a dictionary, but you can't change any items"""

        def __setitem__(self, *args, **kwargs):
                raise RuntimeError("This dict is read-only")

        def clear(self, *args, **kwargs):
                raise RuntimeError("This dict is read-only")

        def pop(self, *args, **kwargs):
                raise RuntimeError("This dict is read-only")

        def popitem(self, *args, **kwargs):
                raise RuntimeError("This dict is read-only")

        def setdefault(self, *args, **kwargs):
                raise RuntimeError("This dict is read-only")

        def update(self, *args, **kwargs):
                raise RuntimeError("This dict is read-only")

