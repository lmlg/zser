cimport cython as cy
from functools import partial
from importlib import import_module
from itertools import chain
import hashlib
import hmac
import mmap
import operator
import struct
from sys import byteorder
from threading import Lock

cdef object S_pack_into = struct.pack_into
cdef object S_unpack_from = struct.unpack_from
cdef object S_calcsize = struct.calcsize

cdef object OP_add = operator.add
cdef object OP_mod = operator.mod
cdef object OP_mul = operator.mul

cdef object OP_eq = operator.eq
cdef object OP_ge = operator.ge
cdef object OP_gt = operator.gt
cdef object OP_le = operator.le
cdef object OP_lt = operator.lt
cdef object OP_ne = operator.ne

cdef object IT_chain = chain
cdef str SYS_endian = byteorder
cdef bint Little_Endian_p = SYS_endian == "little"
cdef object Int_From_Bytes = int.from_bytes
cdef object Bytes_Cls = (bytes, bytearray)

cdef str _WORD_FMT
cdef str _IWORD_FMT

if S_calcsize ("N") == 8:
  # 64-bit architecture
  _WORD_FMT, _IWORD_FMT = "Q", "q"
else:
  # 32-bit architecture
  _WORD_FMT, _IWORD_FMT = "I", "i"

cdef str _WORD_PACK = "=" + _WORD_FMT

cdef object Import_Module = import_module

cdef dict _custom_packers = {}
cdef object _custom_packers_lock = Lock ()
cdef unsigned int _MAX_DISTANCE = 100

cdef object HMAC = hmac.HMAC
cdef object _HASH_METHOD = hashlib.sha256

# Basic types that may be stored inline in lists, sets, dicts and descriptors.
ctypedef fused cnum:
  Py_ssize_t
  size_t
  double

# Integer array types used for hash indexes. They come in variants of
# 2 sizes (32 and 64 bit integers), and also in 2 'flavours': Those
# used for sets (they only store the key offset), and those used for
# dictionaries (store both key and value offsets).

cdef struct array_2I:
  unsigned int hval
  unsigned int key_off

cdef struct array_2Q:
  unsigned long long hval
  unsigned long long key_off

cdef struct array_3I:
  unsigned int hval
  unsigned int key_off
  unsigned int val_off

cdef struct array_3Q:
  unsigned long long hval
  unsigned long long key_off
  unsigned long long val_off

hidx_type = cy.fused_type ("const array_2I*", "const array_2Q*",
                           "const array_3I*", "const array_3Q*")

# Union used for type punning functions used for iterating proxy dicts.
cdef union fn_caster:
  size_t wfn
  dict_iter_fn bfn

# Special object used for detecting misses in dict lookups.
cdef object _SENTINEL = object ()

cdef inline size_t _get_padding (size_t off, size_t size):
  return ((off + size) & ~(size - 1)) - off

cdef _pack_cnum (packer xm, int code, cnum value, bint tag):
  cdef size_t offset, extra, rv
  cdef char *ptr

  offset = xm.offset
  extra = _get_padding (offset + tag, sizeof (value))
  rv = extra + tag + sizeof (value)
  xm.resize (rv)
  ptr = xm.wbytes
  extra += offset

  if tag:
    ptr[offset] = code
    extra += 1

  (<cnum *> (ptr + extra))[0] = value
  xm.bump (rv)

def _pack_int (packer xm, value, tag):
  if IWORD_MIN <= value <= IWORD_MAX:
    # Signed integer.
    _pack_cnum[Py_ssize_t] (xm, tpcode.INT, value, tag)
  elif 0 <= value <= WORD_MAX:
    # Unsigned integer.
    _pack_cnum[size_t] (xm, tpcode.UINT, value, tag)
  else:
    # Bigint.
    bitlen = value.bit_length ()
    rlen = bitlen // 8 + 1
    brepr = value.to_bytes (rlen, SYS_endian, signed = True)
    if tag:
      xm.putb (tpcode.NUM)
    blen = len (brepr)
    xm.pack_struct ("=I" + str (blen) + "s", blen, brepr)

def _pack_float (packer xm, value, tag):
  _pack_cnum[double] (xm, tpcode.FLOAT, value, tag)

cpdef _write_size (buf, size_t offs, size_t sz):
  cdef char *ptr

  ptr = buf
  if sz > 0xff:
    ptr[offs] = 0xff
    memcpy (ptr + offs + 1, &sz, sizeof (sz))
    return 1 + sizeof (sz)
  else:
    ptr[offs] = <unsigned char> (sz)
    return 1

def _pack_str (packer xm, str value, tag):
  cdef char *ptr
  cdef size_t size, offset, prev
  cdef unsigned int kind

  size = len (value)
  kind = STR_KIND (value)
  xm.resize ((size << (kind >> 1)) + 5 + sizeof (size_t))

  ptr = xm.wbytes
  offset = prev = xm.offset

  if tag:
    ptr[offset] = tpcode.STR
    offset += 1

  ptr[offset] = kind
  offset += _write_size (xm.wbytes, offset + 1, size) + 1

  if (kind & 1) == 0:
    # UCS-2 or UCS-4 string.
    offset += _get_padding (offset, kind)
    size <<= kind >> 1
  else:
    # ASCII or Latin-1.
    kind = 1

  memcpy (ptr + offset, PyUnicode_DATA (value), size + kind)
  xm.bump (offset - prev + size + kind)

cdef _pack_bytes (packer xm, value, tag):
  cdef char *ptr
  cdef const char *src
  cdef size_t offset, size, prev

  src = value
  offset = prev = xm.offset
  size = len (src)

  xm.resize (1 + sizeof (size_t) + size)
  ptr = xm.wbytes

  if tag:
    ptr[offset] = tpcode.BYTES if type (value) is bytes else tpcode.BYTEARRAY
    offset += 1

  offset += _write_size (xm.wbytes, offset, size)
  memcpy (ptr + offset, src, size)
  xm.bump (offset - prev + size)

cdef dict _TYPECODES_MAP = {
  float: tpcode.FLOAT,
  str: tpcode.STR,
  bytes: tpcode.BYTES,
  bytearray: tpcode.BYTEARRAY,
  list: tpcode.LIST,
  tuple: tpcode.TUPLE,
  set: tpcode.SET,
  frozenset: tpcode.SET,
  dict: tpcode.DICT,
}

cdef int _inline_pack (obj):
  if obj is None:
    return tpcode.NONE
  elif obj is True:
    return tpcode.TRUE
  elif obj is False:
    return tpcode.FALSE
  return -1

cdef int _type_code (obj, packer xm):
  ret = _inline_pack (obj)
  if ret >= 0:
    return ret
  elif isinstance (obj, int):
    if IWORD_MIN <= obj <= IWORD_MAX:
      return tpcode.INT
    elif 0 <= obj <= WORD_MAX:
      return tpcode.UINT
    return tpcode.NUM

  tmp = xm.id_cache.get (id (obj))
  if tmp is not None:
    return tpcode.BACKREF

  typ = type (obj)
  tmp = _dispatch_type_impl (xm.custom_packers, typ, direction.PACK)
  if tmp is not None:
    return tpcode.CUSTOM
  return _TYPECODES_MAP.get (typ, tpcode.OTHER)

cdef tuple _compute_basic_types (iterable):
  all_ints, all_flts = (None, None)
  for elem in iterable:
    if type (elem) is int:
      all_flts = 0
      if all_ints == 0:
        continue
      if IWORD_MIN <= elem <= IWORD_MAX:
        if all_ints is not None and all_ints > 0:
          all_ints = 0
        elif all_ints is None:
          all_ints = -1
      elif elem <= WORD_MAX:
        if all_ints is not None and all_ints < 0:
          all_ints = 0
        elif all_ints is None:
          all_ints = 1
    elif type (elem) is float:
      all_ints = 0
      if all_flts == 0:
        continue
      all_flts = 1
    else:
      all_ints = all_flts = 0

  return (all_ints, all_flts)

cdef _pack_array (packer xm, value, tag):
  cdef size_t off
  cdef packer m2

  all_ints, all_flts = _compute_basic_types (value)

  if tag:
    xm.putb (tpcode.LIST if type (value) is list else tpcode.TUPLE)

  if all_ints:
    if all_ints < 0:
      xm.putb (tpcode.INT)
      icode = _IWORD_FMT
    else:
      xm.putb (tpcode.UINT)
      icode = _WORD_FMT

    xm.align_to (sizeof (size_t))
    size = len (value)
    xm.pack_struct (_WORD_FMT + str (size) + icode, size, *value)
    return
  elif all_flts:
    xm.putb (tpcode.FLOAT)
    xm.align_to (sizeof (double))
    size = len (value)
    xm.pack_struct (_WORD_FMT + str (size) + "d", size, *value)
    return

  tpcodes = []
  wide = False
  m2 = xm.copy ()

  for elem in value:
    ty = _type_code (elem, xm)
    tpcodes.append (ty)
    if ty in (tpcode.NONE, tpcode.TRUE, tpcode.FALSE):
      continue

    off = m2.offset
    m2.pack (elem, False)
    if off >= 0x4000000:
      wide = True

    tpcodes[-1] |= off << 5

  tplen = len (tpcodes)
  base_fmt = "=c" + _WORD_FMT
  code = b"Q" if wide else b"I"

  xm.pack_struct (base_fmt, code, tplen)
  xm.align_to (sizeof (long long) if wide else sizeof (int))
  xm.pack_struct (str (tplen) + chr (code[0]), *tpcodes)
  if not wide:
    xm.align_to (sizeof (long long))
  xm.bwrite (m2)

# Helper to sort (endian-dependent) offsets.
def _key_by_index (idx, obj):
  return obj[idx]

cdef _pack_set (packer xm, value, tag):
  cdef size_t offset, size, hv
  cdef unsigned int eidx
  cdef packer m2

  all_ints, all_flts = _compute_basic_types (value)

  if tag:
    xm.putb (tpcode.SET)

  offset = xm.offset

  if all_ints or all_flts:
    lst = tuple (sorted (value))
    _pack_array (xm, lst, False)
    return

  offcodes = []
  wide = False
  m2 = xm.copy ()
  eidx = Little_Endian_p

  for elem in value:
    ty = _type_code (elem, xm)
    hv = _xhash (elem, xm.hash_seed)
    if hv >= 0x4000000:
      wide = True

    offcodes.append ([hv, ty])
    if ty in (tpcode.NONE, tpcode.TRUE, tpcode.FALSE):
      continue

    off = m2.offset
    m2.pack (elem, False)
    if off >= 0x4000000:
      wide = True

    offcodes[-1][eidx] |= off << 5

  offcodes.sort (key = partial (_key_by_index, 1 - eidx))
  offcodes = sum (offcodes, [])
  tplen = len (offcodes)
  base_fmt = "=c" + _WORD_FMT
  code = b"Q" if wide else b"I"

  xm.pack_struct (base_fmt, code, tplen)
  xm.align_to (sizeof (long long) if wide else sizeof (int))
  xm.pack_struct (str (tplen) + chr (code[0]), *offcodes)
  if not wide:
    xm.align_to (sizeof (long long))
  xm.bwrite (m2)

cdef _pack_dict (packer xm, value, tag):
  cdef size_t hv
  cdef unsigned int eidx
  cdef packer m2

  if tag:
    xm.putb (tpcode.DICT)

  offset = xm.offset
  offcodes = []
  wide = False
  m2 = xm.copy ()
  eidx = Little_Endian_p << 1

  for key, val in value.items ():
    hv = _xhash (key, xm.hash_seed)
    t1 = _type_code (key, xm)
    t2 = _type_code (val, xm)

    if hv >= 0x4000000:
      wide = True

    offcodes.append ([hv, t1, t2])
    if t1 not in (tpcode.NONE, tpcode.TRUE, tpcode.FALSE):
      off = m2.offset
      m2.pack (key, False)
      if off >= 0x4000000:
        wide = True
      offcodes[-1][1] |= off << 5

    if t2 not in (tpcode.NONE, tpcode.TRUE, tpcode.FALSE):
      off = m2.offset
      m2.pack (val, False)
      if off >= 0x4000000:
        wide = True
      offcodes[-1][eidx] |= off << 5

  offcodes.sort (key = partial (_key_by_index, 2 - eidx))
  offcodes = sum (offcodes, [])
  tplen = len (offcodes)
  base_fmt = "=c" + _WORD_FMT
  code = b"Q" if wide else b"I"

  xm.pack_struct (base_fmt, code, tplen)
  xm.align_to (sizeof (long long) if wide else sizeof (int))
  xm.pack_struct (str (tplen) + chr (code[0]), *offcodes)
  if not wide:
    xm.align_to (sizeof (long long))
  xm.bwrite (m2)

cdef inline object _encode_str (object x):
  return PyUnicode_AsEncodedString (x, "utf8", cy.NULL)

cdef _write_type (packer xm, typ):
  cdef size_t sz

  path = _encode_str (typ.__module__ + "." + typ.__name__)
  sz = len (path)

  if xm.import_key is not None:
    # Include the checksum key in the stream.
    md = _encode_str (HMAC(xm.import_key, path, _HASH_METHOD).hexdigest())
    xm.pack_struct ("I%ds" % len (md), len (md), md)

  xm.resize (sizeof (size_t) + 1 + sz)
  xm.bump (_write_size (xm.wbytes, xm.offset, sz))
  xm.bwrite (path)

cdef dict _obj_vars (obj):
  ret = getattr (obj, "__dict__", _SENTINEL)
  if ret is not _SENTINEL:
    return ret

  ret = getattr (obj, "__slots__", _SENTINEL)
  if ret is not _SENTINEL:
    return {key: getattr (obj, key, None) for key in ret}

  raise TypeError ("cannot get attributes from object of type %r" % type (obj))

cdef _pack_generic (packer xm, value, tag):
  cdef size_t off, extra
  cdef packer m2

  if tag:
    xm.putb (tpcode.OTHER)

  attrs = _obj_vars (value)
  _write_type (xm, type (value))
  m2 = xm.copy ()
  data = []
  wide = 0

  for key, val in attrs.items ():
    key = _encode_str (key)
    slen = len (key)
    if slen >= 0x400000:
      wide = 1

    ty = _type_code (val, xm)
    data.extend ((slen, ty))

    if ty not in (tpcode.NONE, tpcode.TRUE, tpcode.FALSE):
      off = m2.offset
      m2.pack (val, False)
      data[-1] |= off << 5
      if off >= 0x400000:
        wide = 1

  keys = _encode_str ("".join (attrs.keys ()))
  nelem = len (data)
  xm.align_to (sizeof (long long))
  xm.pack_struct ("II" + str (nelem) + ("Q" if wide else "I"),
                  ((nelem << 1) | wide), len (keys), *data)
  xm.bwrite (keys)
  xm.align_to (sizeof (long long))
  xm.bwrite (m2)

cdef inline size_t _upsize (size_t value):
  # Round up 'value' to the next power of 2.
  cdef size_t off

  off = 1
  while off <= 32:
    value |= value >> off
    off <<= 1

  return value + 1

cdef dict _BASIC_PACKERS = {
  int: _pack_int,
  float: _pack_float,
  str: _pack_str,
  bytes: _pack_bytes,
  bytearray: _pack_bytes,
  list: _pack_array,
  tuple: _pack_array,
  set: _pack_set,
  frozenset: _pack_set,
  dict: _pack_dict
}

cdef object _get_import_key (object key):
  if key is not None:
    if isinstance (key, str):
      key = _encode_str (key)
    elif not isinstance (key, bytes):
      raise TypeError ("import_key must be a string or bytes")

  return key

cdef class packer:
  """
  Class used to pack arbitrary objects into a byte stream.
  Instances of this class are responsible of keeping certain invariants,
  the most important being that objects are packed at aligned boundaries,
  to make the unpacking operations fast and safe across architectures
  with different constraints.
  """

  cdef size_t offset
  cdef bytearray wbytes
  cdef size_t wlen
  cdef dict id_cache
  cdef size_t hash_seed
  cdef dict custom_packers
  cdef object import_key

  def __init__ (self, offset = 0, id_cache = None, hash_seed = 0,
      custom_packers = None, initial_size = 8, import_key = None):
    """
    Constructs a packer.

    :param int offset *(default 0)*: Starting offset at which objects are
      meant to be packed into.
    
    :param dict id_cache *(default None)*: Mapping from objects id to offsets.
      Needed to correctly pack cyclic objects.

    :param int hash_seed *(default 0)*: Initial value used to hash objects.

    :param dict custom_packers *(default None)*: Mapping from types to
      packing functions.

    :param int initial_size: Starting size of the byte stream.

    :param import_key *(default None)*: Secret key used to compute the checksum
      when importing foreign modules. Can be ``None`` if no checking is desired.
    """
    self.offset = offset & (sizeof (long long) - 1)
    self.wbytes = bytearray (_upsize (initial_size + offset))
    self.id_cache = id_cache if id_cache is not None else {}
    self.hash_seed = hash_seed
    if custom_packers is not None:
      self.custom_packers = custom_packers
    else:
      self.custom_packers = _custom_packers.copy ()
    self.wlen = self.offset
    self.import_key =  _get_import_key (import_key)

  cpdef copy (self):
    """
    Create an equivalent copy of the packer. Useful when packing complex
    objects that need constituent members to be packed separatedly without
    modifying the initial packer.
    """
    return packer (0, id_cache = self.id_cache.copy (),
                   hash_seed = self.hash_seed,
                   custom_packers = self.custom_packers,
                   initial_size = 8, import_key = self.import_key)

  cpdef resize (self, size_t extra):
    """
    Resize the underlying byte stream so that it has enough room for an
    additional ``extra`` bytes.
    """
    nsize = self.wlen + extra
    if (nsize >= <size_t> (len (self.wbytes)) and
        PyByteArray_Resize (self.wbytes, _upsize (nsize)) < 0):
      raise MemoryError

  cpdef bump (self, size_t off):
    "Bump the internal offset of the stream by ``off`` bytes."
    self.wlen += off
    self.offset += off

  cpdef putb (self, unsigned char bx):
    "Write a single byte to the stream."

    self.resize (1)
    self.wbytes[self.wlen] = bx
    self.bump (1)

  cpdef zpad (self, size_t size):
    "Write ``size`` zeroes to the stream."
    self.resize (size)
    self.bump (size)

  cpdef align_to (self, size_t size):
    "Pad the stream so that the current position is aligned to ``size`` bytes."
    self.zpad (_get_padding (self.offset, size))

  @cy.final
  cdef _pack_struct (self, fmt, tuple args):
    cdef size_t size

    size = S_calcsize (fmt)
    self.resize (size)
    S_pack_into (fmt, self.wbytes, self.wlen, *args)
    self.bump (size)

  def pack_struct (self, fmt, *args):
    "Same as calling ``struct.pack_into`` with the byte stream and offset."
    self._pack_struct (fmt, args)

  cpdef bwrite (self, obj):
    """
    Write a binary object to the stream.
    If ``obj`` is itself a packer, then concatenate its stream to ours.
    """
    cdef size_t size

    if isinstance (obj, packer):
      obj = (<packer>obj).as_bytearray ()

    size = len (obj)
    self.resize (size)
    self.wbytes[self.wlen:self.wlen + size] = obj
    self.bump (size)

  cpdef as_bytearray (self):
    "Return a copy of the packer's byte stream so far."
    return self.wbytes[:self.wlen]

  cpdef pack (self, obj, tag = True):
    """
    Pack an arbitrary object in the byte stream.
    if ``tag`` is true, a code indicating the object's type is prepended.
    """
    cdef type ty
    cdef size_t prev

    prev = self.offset
    obj_id = id (obj)
    off = self.id_cache.get (obj_id)
    if off is not None:
      self.putb (tpcode.BACKREF) if tag else None
      self.pack_struct (_WORD_PACK, off)
      return self.offset - prev

    ty = type (obj)
    if ty not in (int, float, str, bytes, bytearray):
      self.id_cache[obj_id] = prev

    try:
      fn = _BASIC_PACKERS.get (ty, None)
      if fn:
        fn (self, obj, tag)
        return self.offset - prev

      code = _inline_pack (obj)
      if code >= 0:
        self.putb (code)
        return 1

      fn = _dispatch_type (ty, direction.PACK)
      if fn is not None:
        if tag:
          self.putb (tpcode.CUSTOM)

        _write_type (self, ty)
        self.align_to (sizeof (long long))
        fn (self, obj)
      else:
        _pack_generic (self, obj, tag)

      return self.offset - prev
    except:
      self.id_cache.pop (obj_id, None)
      raise

cdef inline object _cnum_unpack (proxy_handler self, size_t offs, cnum value):
  cdef size_t extra

  extra = _get_padding (offs, sizeof (value))
  self._assert_len (offs + extra + sizeof (value))
  return (<const cnum*> (self.base + offs + extra))[0]

cdef class proxy_handler:
  """
  Class used to manage an underlying mapping so that objects can be safely
  and efficiently proxied.
  As a counterpart to the ``packer`` class, a ``proxy_handler`` ensures that
  proxy objects have enough room in their backing, and that their lifetimes
  don't extend beyond the mapping's.
  """

  cdef object mbuf
  cdef size_t offset
  cdef size_t max_size
  cdef size_t hash_seed
  cdef char *base
  cdef dict custom_packers
  cdef bint rdwr
  cdef bint verify_str
  cdef object import_key

  def __init__ (self, mapping, offset = 0, size = None, rw = False,
      hash_seed = 0, verify_str = False, import_key = None):
    """
    Constructs a proxy_handler.

    :param mapping: The mapping object. If the object has a ``fileno`` method,
      it will be assumed to be a file, and its file descriptor will be used
      with ``mmap``. Otherwise, it will default to using the ``memoryview``
      interface.

    :param int offset: The starting offset for the mapping object.

    :param size: The maximum size to be used for the mapping. If ``None``,
      then no limits will be assumed.

    :param bool rw *(default False)*: Whether the mapping is read-write.
      If ``False``, the mapping will be assumed to be read-ony, and no
      modifications will be allowed.

    :param int hash_seed *(default 0)*: See ``packer.__init__``.

    :param bool verify_str *(default False)*: Whether to check for strings
      consistency (unicode-wise) when unpacking them.

    :param import_key *(default None)*: See ``packer.__init__``.
    """
    cdef const unsigned char[:] p0

    if hasattr (mapping, "fileno"):
      if size is None:
        size = 0

      self.offset = offset
      offset = offset - (offset % mmap.PAGESIZE)
      acc = mmap.PROT_WRITE if rw else mmap.PROT_READ
      mbuf = mmap.mmap (mapping.fileno (), size, offset = offset,
                        flags = mmap.MAP_SHARED, access = acc)
      self.mbuf = memoryview (mbuf)
    else:
      self.mbuf = memoryview (mapping)
      if rw and self.mbuf.readonly:
        raise BufferError ("memory mapping is read-only")
      self.offset = offset
      if size is not None:
        self.mbuf = self.mbuf[self.offset:size]

    self.rdwr = bool (rw)
    self.verify_str = bool (verify_str)
    self.max_size = len (self.mbuf)
    self.hash_seed = hash_seed
    p0 = self.mbuf
    self.base = <char *>&p0[0]
    self.custom_packers = _custom_packers.copy ()
    self.import_key = _get_import_key (import_key)

  def __len__ (self):
    return self.max_size

  @cy.final
  cdef object _assert_len (self, size_t size):
    if self.max_size < size:
      raise ValueError ("buffer too small")

  def __getbuffer__ (self, Py_buffer *buf, int flags):
    PyObject_GetBuffer (self.mbuf, buf, flags)

  def __releasebuffer__ (self, Py_buffer *buf):
    PyBuffer_Release (buf)

  def unpack_struct (self, fmt, off):
    "Same as calling ``struct.unpack_from`` using the proxy as a buffer."
    return S_unpack_from (fmt, self, off)

  @staticmethod
  def struct_size (fmt):
    return S_calcsize (fmt)

  def __getitem__ (self, ix):
    "Return the byte at position ``ix``."
    return self.mbuf[ix]

  cdef _unpack_with_code (self, size_t offset, unsigned int code):
    cdef size_t size, rel_off
    cdef unsigned int ilen

    if code == tpcode.INT:
      return _cnum_unpack[Py_ssize_t] (self, offset, 0)
    elif code == tpcode.UINT:
      return _cnum_unpack[size_t] (self, offset, 0)
    elif code == tpcode.FLOAT:
      return _cnum_unpack[double] (self, offset, 0)
    elif code == tpcode.NUM:
      self._assert_len (offset + sizeof (ilen))
      memcpy (&ilen, self.base + offset, sizeof (ilen))
      offset += sizeof (ilen)
      return Int_From_Bytes (self.mbuf[offset:offset + ilen],
                             SYS_endian, signed = True)
    elif code == tpcode.STR:
      return proxy_str._make (self, offset)
    elif code in (tpcode.BYTES, tpcode.BYTEARRAY):
      self._assert_len (offset + 1)
      size = self.base[offset]
      if size == 0xff:
        self._assert_len (offset + 1 + sizeof (size))
        memcpy (&size, self.base + offset + 1, sizeof (size))
        offset += sizeof (size)

      offset += 1
      return Bytes_Cls[code - tpcode.BYTES] (self.mbuf[offset:offset + size])
    elif code == tpcode.NONE:
      return None
    elif code == tpcode.TRUE:
      return True
    elif code == tpcode.FALSE:
      return False
    elif code == tpcode.LIST or code == tpcode.TUPLE:
      return proxy_list._make (self, offset, code == tpcode.LIST)
    elif code == tpcode.SET:
      return proxy_set._make (self, offset)
    elif code == tpcode.DICT:
      return proxy_dict._make (self, offset)
    elif code == tpcode.BACKREF:
      self._assert_len (offset + sizeof (offset))
      memcpy (&offset, self.base + offset, sizeof (offset))
      return self._unpack (offset)
    elif code == tpcode.OTHER:
      return _proxy_obj (self, offset)
    elif code == tpcode.CUSTOM:
      typ = _read_type (self, &offset)
      fn = _dispatch_type_impl (self.custom_packers, typ, direction.UNPACK)
      if fn is None:
        raise TypeError ("cannot unpack type %r" % typ)
      return fn (typ, self, offset + _get_padding (offset,
                                                   sizeof (long long)))
    raise TypeError ("Cannot unpack typecode %r" % code)

  cdef object _unpack_with_data (self, unsigned long long data,
                                 proxy_list indices):
    return self._unpack_with_code ((data >> 5) + indices.offset +
                                   indices.sub_off, data & 0x1f)

  @cy.final
  cdef object _unpack (self, size_t offs):
    self._assert_len (offs)
    return self._unpack_with_code (offs + 1, <unsigned char> (self.base[offs]))

  cpdef unpack (self):
    "Unpack an object at the proxy's current offset."
    return self._unpack (self.offset)

  def unpack_from (self, off):
    "Unpack an object from the proxy at a specified offset."
    return self._unpack (off)

  def unpack_as (self, code, off = None):
    """
    Unpack an object from the proxy using a specific type, and (optionally),
    at a specific offset.
    """
    return self._unpack_with_code (self.offset if off is None else off, code)

cdef inline int atomic_cas_f (void *ptr, double exp, double nval) except -1:
  cdef int ret

  ret = _atomic_cas_f (ptr, exp, nval)
  if ret < 0:
    raise RuntimeError ("platform does not support CAS for doubles")
  return ret

cdef inline double atomic_add_f (void *ptr, double value):
  cdef double tmp

  while 1:
    tmp = (<double *>ptr)[0]
    if atomic_cas_f (ptr, tmp, tmp + value):
      return tmp
    atomic_fence ()

cdef class proxy_list:
  cdef proxy_handler proxy
  cdef size_t offset
  cdef size_t sub_off
  cdef size_t size
  cdef unsigned int code
  cdef Py_ssize_t step
  cdef bint mutable

  @staticmethod
  cdef proxy_list _make (proxy_handler proxy, size_t off, bint mutable):
    cdef proxy_list self
    cdef size_t esz
    cdef unsigned int ty
    cdef bint rdwr

    self = proxy_list.__new__ (proxy_list)
    self.proxy = proxy
    self.offset = off

    ty = self.proxy[self.offset]
    if ty <= tpcode.FLOAT:
      # Inline objects: (s)size_t and double's
      esz = sizeof (double) if ty == tpcode.FLOAT else sizeof (size_t)
      self.offset += _get_padding (self.offset + 1, esz) + 1
      self.proxy._assert_len (self.offset + sizeof (size_t))
      self.size = (<size_t *> (self.proxy.base + self.offset))[0]
      self.offset += sizeof (size_t)
      self.sub_off = 0
      self.proxy._assert_len (self.offset + self.size * esz)
    else:
      # Indirect references to objects.
      esz = sizeof (int) if ty == b"I" else sizeof (long long)
      self.proxy._assert_len (self.offset + 1 + sizeof (size_t))
      memcpy (&self.size, self.proxy.base + self.offset + 1, sizeof (size_t))
      self.offset += sizeof (size_t) + 1
      self.offset += _get_padding (self.offset, esz)

      self.sub_off = self.size * esz
      if esz == sizeof (int):
        self.sub_off += _get_padding (self.offset + self.sub_off,
                                      sizeof (long long))
      self.proxy._assert_len (self.offset + self.sub_off)

    self.code = ty
    self.step = 1
    self.mutable = mutable and self.proxy.rdwr
    return self

  def __len__ (self):
    return self.size

  @cy.final
  cdef inline object _c_index (self, Py_ssize_t pos, unsigned int code):
    cdef char *ptr
    cdef unsigned long long data

    pos *= self.step
    ptr = self.proxy.base + self.offset

    if code == tpcode.INT:
      if self.mutable:
        atomic_fence ()
      return (<Py_ssize_t *>ptr)[pos]
    elif code == tpcode.UINT:
      if self.mutable:
        atomic_fence ()
      return (<size_t *>ptr)[pos]
    elif code == tpcode.FLOAT:
      if self.mutable:
        atomic_fence ()
      return (<double *>ptr)[pos]
    else:
      if self.code == b"I":
        data = (<unsigned int *>ptr)[pos]
      else:
        data = (<unsigned long long *>ptr)[pos]

      return self.proxy._unpack_with_data (data, self)

  @cy.cdivision (True)
  def __getitem__ (self, idx):
    cdef Py_ssize_t pos, n, start, end, step, rsize
    cdef proxy_list rv

    if isinstance (idx, int):
      pos = idx
      n = self.size

      if pos < 0:
        pos += n
        if pos < 0:
          raise IndexError ("index out of bounds")
      elif pos >= n:
        raise IndexError ("index out of bounds")

      return self._c_index (pos, self.code)
    elif isinstance (idx, slice):
      PySlice_GetIndices (idx, self.size, &start, &end, &step)

      rv = proxy_list.__new__ (proxy_list)
      rv.proxy = self.proxy
      rv.code = self.code

      rsize = (end - start) // step
      if ((end - start) % step) != 0:
        rsize += 1

      rv.size = rsize
      rv.offset = self.offset

      if rv.code == tpcode.FLOAT:
        start *= sizeof (double)
      elif rv.code == tpcode.INT or rv.code == tpcode.UINT:
        start *= sizeof (size_t)
      elif rv.code == b"I":
        start *= sizeof (int)
      else:
        start *= sizeof (long long)

      rv.offset += start * self.step
      rv.sub_off = self.sub_off + self.offset - rv.offset
      rv.step = step * self.step
      return rv
    raise TypeError ("index must be an integer or slice")

  cdef Py_ssize_t _mutable_idx (self, idx) except -1:
    cdef Py_ssize_t pos
    cdef char *ptr

    if not self.mutable:
      raise TypeError ("cannot modify read-only proxy list")
    elif self.code > tpcode.FLOAT:
      raise TypeError ("cannot modify proxy list with indirect objects")

    pos = idx
    if pos < 0:
      pos += self.size
      if pos < 0:
        raise IndexError ("index out of bounds")
    elif <size_t>pos >= self.size:
      raise IndexError ("index out of bounds")

    return pos * self.step

  def __setitem__ (self, idx, value):
    cdef Py_ssize_t pos
    cdef char *ptr

    pos = self._mutable_idx (idx)
    ptr = self.proxy.base + self.offset

    if self.code == tpcode.INT:
      (<Py_ssize_t *>ptr)[pos] = value
    elif self.code == tpcode.UINT:
      (<size_t *>ptr)[pos] = value
    elif self.code == tpcode.FLOAT:
      (<double *>ptr)[pos] = value
    else:
      raise TypeError ("cannot modify non-primitive proxy list")

    atomic_fence ()

  def atomic_cas (self, idx, exp, nval):
    """
    Atomically compare the value at ``idx``, and if it's equal to ``exp``, set
    it to ``nval``. Returns True if the operation was successful.
    """
    cdef Py_ssize_t pos, rv
    cdef char *ptr

    pos = self._mutable_idx (idx)
    ptr = self.proxy.base + self.offset

    if self.code == tpcode.INT:
      rv = atomic_cas_i ((<Py_ssize_t *>ptr) + pos, exp, nval)
    elif self.code == tpcode.UINT:
      rv = atomic_cas_I ((<size_t *>ptr) + pos, exp, nval)
    elif self.code == tpcode.FLOAT:
      rv = atomic_cas_f ((<double *>ptr) + pos, exp, nval)
    else:
      raise TypeError ("atomics are not supported for this proxy list's values")

    return True if rv != 0 else False

  def atomic_add (self, idx, value):
    """
    Atomically add ``value`` to the value at ``idx``, returning the previous
    value at that position.
    """
    cdef Py_ssize_t pos
    cdef char *ptr

    pos = self._mutable_idx (idx)
    ptr = self.proxy.base + self.offset

    if self.code == tpcode.INT:
      return atomic_add_i ((<Py_ssize_t *>ptr) + pos, value)
    elif self.code == tpcode.UINT:
      return atomic_add_I ((<size_t *>ptr) + pos, value)
    elif self.code == tpcode.FLOAT:
      return atomic_add_f ((<double *>ptr) + pos, value)
    else:
      raise TypeError ("atomics are not supported for this proxy list's values")

  def __hash__ (self):
    return _xhash (self, self.proxy.hash_seed)

  def __iter__ (self):
    cdef size_t i
    cdef unsigned int code

    code = self.code
    for i in range (self.size):
      yield self._c_index (i, code)

  def __str__ (self):
    return "[%s]" % ",".join ([str (x) for x in self])

  def __repr__ (self):
    return "proxy_list(%s)" % self

  def __add__ (self, x):
    cdef bint rdwr
    cdef type typ

    if not isinstance (x, proxy_list):
      typ = list if (<proxy_list>self).mutable else tuple
      if typ is not type (x):
        raise TypeError ("cannot add proxy_list to %r" % type(x).__name__)
    else:
      rdwr = (<proxy_list>x).mutable
      typ = list if rdwr else tuple
      if ((isinstance (self, proxy_list) and
          rdwr != (<proxy_list>self).mutable) or
            (not isinstance (self, proxy_list) and
              not isinstance (self, typ))):
        raise TypeError ("cannot add proxy lists of different mutability")

    return typ (IT_chain (self, x))

  def copy (self):
    return list (self) if self.mutable else self

  def index (self, value, start = 0, stop = WORD_MAX):
    cdef size_t istart, istop, n
    cdef unsigned int code

    istart, istop = start, stop
    n = self.size
    istop = min (istop, n)
    code = self.code

    while istart < istop:
      if self._c_index (istart, code) == value:
        return istart
      istart += 1

    raise ValueError ("%r is not in list" % value)

  def __contains__ (self, value):
    cdef size_t i
    cdef unsigned int code

    code = self.code
    for i in range (self.size):
      if self._c_index (i, code) == value:
        return True
    return False

  def count (self, value):
    cdef size_t i, n
    cdef unsigned int code

    n = 0
    code = self.code
    for i in range (self.size):
      if self._c_index (i, code) == value:
        n += 1
    return n

  @cy.final
  cdef int _cmp (self, x, bint err, bint eq) except -2:
    cdef size_t alen, blen, i

    if not isinstance (x, (tuple, list, proxy_list)):
      if err:
        raise TypeError ("cannot compare types: (%r and %r)" %
                         (type(self).__name__, type(x).__name__))
      return -1
    elif self is x:
      return 0

    alen = self.size
    blen = len (x)
    if eq and alen != blen:
      return 1

    for i in range (min (alen, blen)):
      a = self._c_index (i, self.code)
      b = x[i]

      if a is b:
        pass
      elif a < b:
        return -1
      elif a > b:
        return 1

    if alen < blen:
      return -1
    elif alen > blen:
      return 1
    else:
      return 0

  def __eq__ (self, x):
    if isinstance (self, proxy_list):
      return (<proxy_list>self)._cmp (x, False, True) == 0
    return (<proxy_list>x)._cmp (self, False, True) == 0

  def __lt__ (self, x):
    return self._cmp (x, True, False) < 0

  def __le__ (self, x):
    return self._cmp (x, True, False) <= 0

  def __gt__ (self, x):
    return self._cmp (x, True, False) > 0

  def __ge__ (self, x):
    return self._cmp (x, True, False) >= 0

  @cy.final
  cdef _unproxy (self):
    unproxy_ = unproxy
    typ = list if self.mutable else tuple
    return typ (unproxy_ (x) for x in self)

###################################

cdef object _verify_str (void *ptr, size_t size, unsigned int kind):
  cdef size_t i

  if kind == 3:
    # ASCII string.
    for i in range (size):
      if (<const unsigned char *>ptr)[i] > 0x7f:
        raise ValueError ("invalid codepoint for ASCII string")
  elif kind == 2:
    # UCS-2 string.
    for i in range (size):
      if ((<const unsigned short *>ptr)[i] >= 0xd800 and
          (<const unsigned short *>ptr)[i] <  0xe000):
        raise ValueError ("invalid codepoint for UCS-2 string")

cdef class proxy_str:
  cdef proxy_handler proxy
  cdef str uobj

  @staticmethod
  cdef proxy_str _make (proxy_handler proxy, size_t off):
    cdef proxy_str self
    cdef size_t size
    cdef unsigned int kind, orig_kind

    self = proxy_str.__new__ (proxy_str)
    self.proxy = proxy

    orig_kind = kind = self.proxy[off]
    size = self.proxy[off + 1]
    if size == 0xff:
      self.proxy._assert_len (off + 2 + sizeof (size))
      memcpy (&size, self.proxy.base + off + 2, sizeof (size))
      off += sizeof (size_t)

    off += 2
    if (kind & 1) == 0:
      off += _get_padding (off, kind)
    else:
      kind = 1

    self.proxy._assert_len (off + size + kind)
    if self.proxy.verify_str:
      _verify_str (self.proxy.base + off, size, orig_kind)

    self.uobj = STR_NEW (orig_kind, size, self.proxy.base + off)
    return self

  def __dealloc__ (self):
    if self.uobj is not None:
      STR_FINI (self.uobj)

  def __str__ (self):
    return _PyUnicode_Copy (self.uobj)

  def __repr__ (self):
    return repr (self.uobj)

  def __len__ (self):
    return len (self.uobj)

  def __getattribute__ (self, attr):
    # We must prevent the unicode object from ever leaking out, since it's
    # susceptible to crashes when used outside the proxy container.
    meth = getattr (str, attr)
    def fn (*args, **kwargs):
      ret = meth (self.uobj, *args, **kwargs)
      if type (ret) is list or type (ret) is tuple:
        try:
          ix = ret.index (self.uobj)
          if type (ret) is list:
            ret[ix] = str (self)
          else:
            ret = ret[0:ix] + (str (self), *ret[ix + 1:])
        except ValueError:
          pass
      elif ret is self.uobj:
        ret = self
      return ret
    return fn

  def __getitem__ (self, ix):
    cdef Py_ssize_t start, end, step, slen
    cdef proxy_str rv

    if not isinstance (ix, slice):
      ret = self.uobj[ix]
      return ret if ret is not self.uobj else self

    slen = len (self.uobj)
    PySlice_GetIndices (ix, slen, &start, &end, &step)
    if step != 1:
      ret = self.uobj[ix]
      return ret if ret is not self.uobj else self
    elif start == 0 and end == slen:
      return self
    elif start >= end:
      return ''

    rv = proxy_str.__new__ (proxy_str)
    rv.proxy = self.proxy
    rv.uobj = STR_NEW (STR_KIND (self.uobj), min (end - start, slen),
                       (<char *>PyUnicode_DATA (self.uobj)) + start)
    return rv

  # These arithmetic operators are placeholders until we can install
  # the real implementations once the 'proxy_str' type is finalized.
  def __add__ (self, x):
    return self

  def __mod__ (self, x):
    return self

  def __mul__ (self, x):
    return self

  def __contains__ (self, x):
    return x in self.uobj

  def __dir__ (self):
    return dir (str)

  def __hash__ (self):
    return hash (self.uobj)

  @staticmethod
  cdef object _cmp_impl (self, x, fn):
    cdef proxy_str this

    if isinstance (self, proxy_str):
      this = <proxy_str>self
      if isinstance (x, proxy_str):
        return fn (this.uobj, (<proxy_str>x).uobj)
      elif isinstance (x, str):
        return fn (this.uobj, x)
      else:
        return fn (str (this), x)
    else:
      this = <proxy_str>x
      if isinstance (self, proxy_str):
        return fn ((<proxy_str>self).uobj, this.uobj)
      elif isinstance (self, str):
        return fn (self, this.uobj)
      else:
        return fn (self, str (this))

  def __eq__ (self, x):
    return proxy_str._cmp_impl (self, x, OP_eq)

  def __ge__ (self, x):
    return proxy_str._cmp_impl (self, x, OP_ge)

  def __gt__ (self, x):
    return proxy_str._cmp_impl (self, x, OP_gt)

  def __iter__ (self):
    for ch in self.uobj:
      yield ch

  def __le__ (self, x):
    return proxy_str._cmp_impl (self, x, OP_le)

  def __lt__ (self, x):
    return proxy_str._cmp_impl (self, x, OP_lt)

  def __ne__ (self, x):
    return proxy_str._cmp_impl (self, x, OP_ne)

# The following is a kludge to support arbitrary argument order in
# arithmetic operators. We need to patch things this way because not
# all Cython versions can be convinced.

cdef str _proxy_str_op_impl (self_, x, typ, bint self_type, fn):
  cdef proxy_str this

  # For standard operators (i.e: 'str.__add__'), we can use the raw unicode
  # object, since we know there's no danger there. Otherwise, for custom
  # types, we have to copy into a fresh object.
  this = None
  if isinstance (self_, proxy_str):
    if isinstance (x, typ):
      this = self_
      ret = fn (this.uobj, x)
    elif self_type and isinstance (x, proxy_str):
      this = self_
      ret = fn (this.uobj, (<proxy_str>x).uobj)
    else:
      ret = fn (str (self_), x)
  elif isinstance (self_, typ):
    this = x
    ret = fn (self_, this.uobj)
  else:
    ret = fn (self_, str (x))

  return ret if this is None or ret is not this.uobj else this

cdef _proxy_str_add (x, y):
  return _proxy_str_op_impl (x, y, str, True, OP_add)

cdef _proxy_str_mod (x, y):
  return _proxy_str_op_impl (x, y, str, False, OP_mod)

cdef _proxy_str_mul (x, y):
  return _proxy_str_op_impl (x, y, int, False, OP_mul)

# Install the new operators.
TYPE_PATCH (<PyTypeObject *>proxy_str, _proxy_str_add,
            _proxy_str_mod, _proxy_str_mul)

cdef inline size_t _rotate_hash (size_t code, size_t nbits):
  return (code << nbits) | (code >> (sizeof (size_t) * 8 - nbits))

cdef inline size_t _mix_hash (size_t h1, size_t h2):
  return _rotate_hash (h1, 5) ^ h2

cdef inline size_t _hash_buf (const void *ptr, size_t nbytes):
  cdef size_t ret

  ret = nbytes
  for i in range (nbytes):
    ret = (ret << 9) | (ret >> (sizeof (size_t) * 8 - 9))
    ret += (<const unsigned char *>ptr)[i]

  return ret if ret != 0 else WORD_MAX

cdef inline size_t _hash_str (str sobj):
  cdef unsigned int kind

  kind = STR_KIND (sobj)
  if (kind & 1) == 1:
    kind = 1
  return _hash_buf (PyUnicode_DATA (sobj), len (sobj) * kind)

cdef inline size_t _hash_flt (double flt):
  cdef double ipart

  if modf (flt, &ipart) == 0:
    return <size_t> (WORD_MAX & (<long long>flt))
  return _hash_buf (&flt, sizeof (flt))

cdef dict _HASH_VALUES = {}
for code, *ty in ((0x1073952, frozenset, proxy_set),
                  (0x81603094, tuple, proxy_list)):
  for typ in ty:
    _HASH_VALUES[typ] = code
del code
del ty

cdef size_t _xhash (obj, size_t seed) except 0:
  cdef size_t ret
  cdef object ty

  if obj is None:
    ret = 1
  elif isinstance (obj, int):
    try:
      ret = obj
    except OverflowError:
      ret = obj & WORD_MAX
  elif isinstance (obj, float):
    ret = _hash_flt (obj)
  elif isinstance (obj, str):
    ret = _hash_str (<str>obj)
  elif isinstance (obj, proxy_str):
    ret = _hash_str ((<proxy_str>obj).uobj)
  elif isinstance (obj, proxy_dict):
    ret = hash (obj)
  else:
    ty = type (obj)
    if isinstance (obj, proxy_list):
      if (<proxy_list>obj).mutable:
        raise TypeError ("cannot hash mutable proxy list")

    code = _HASH_VALUES.get (ty)
    if code is None:
      raise TypeError ("cannot hash object of type %s" % ty.__name__)

    ret = code
    for val in obj:
      ret = _mix_hash (ret, _xhash (val, seed))

  ret = _mix_hash (seed, ret)
  return ret if ret != 0 else 1

def xhash (obj, seed = 0):
  """
  Produce a hash code for an object that is stable (i.e: independent of
  environment variables). Needed to mantain consistency in hash values
  across different processes. The `seed` parameter is a starting value for
  the computation. May be used to prevent pathological cases.
  """
  return _xhash (obj, seed)

#######################################

cdef inline Py_ssize_t _double_diff (double x, double y):
  cdef double ret

  ret = x - y
  if not isnan (ret):
    return -1 if ret < 0 else ret != 0

  # The result can be NaN if:
  # One of the arguments is NaN
  # x and y are infinity with the same sign

  if isinf (x):
    if isinf (y):
      # inf - inf
      return 0 if x == y else -1 if x > y else 1
    else:
      # inf > nan; -inf < nan
      return x > 0
  elif isnan (y):
    # nan - nan
    return 0
  else:
    # nan < inf; nan > -inf
    return -1 if x > 0 else 1

cdef int _cnum_find_sorted (const unsigned char *ptr, size_t n, obj,
                            cnum value, cnum tmp):
  cdef size_t i, step
  cdef Py_ssize_t cmpr

  try:
    value = obj
  except (TypeError, OverflowError):
    return 0

  i = 0
  while i < n:
    step = (i + n) >> 1
    tmp = (<const cnum *>ptr)[step]
    if cnum is double:
      cmpr = _double_diff (tmp, value)
    else:
      cmpr = <Py_ssize_t> (tmp - value)

    if cmpr == 0:
      return 1
    elif cmpr > 0:
      n = step - 1
      step = min (step >> 2, <size_t>64)
      while step > 0:
        tmp = (<const cnum *>ptr)[n]
        if cnum is double:
          cmpr = _double_diff (tmp, value)
        else:
          cmpr = <Py_ssize_t> (tmp - value)

        if cmpr > 0:
          step -= 1
          n -= 1
        else:
          return cmpr == 0
      n += 1
    else:
      i = step + 1
      step = min (step >> 2, <size_t>64)
      while step > 0:
        tmp = (<const cnum *>ptr)[i]
        if cnum is double:
          cmpr = _double_diff (tmp, value)
        else:
          cmpr = <Py_ssize_t> (tmp - value)

        if cmpr < 0:
          step -= 1
          i += 1
        else:
          return cmpr == 0

  return 0

@cy.cdivision (True)
@cy.nogil
cdef size_t _find_hidx (hidx_type hidxs, size_t hval, size_t n):
  cdef size_t i, step, tmp

  i = 0
  while i < n:
    step = (i + n) >> 1
    tmp = hidxs[step].hval

    if tmp == hval:
      while step > 0:
        if hidxs[step - 1].hval != tmp:
          break
        step -= 1
      return step + 1
    elif tmp > hval:
      n = step - 1
      step = min (step >> 2, <size_t>512 // sizeof (hidxs[0]))
      while step > 0:
        tmp = hidxs[n].hval
        if tmp > hval:
          step -= 1
          n -= 1
        elif tmp == hval:
          while n > 0:
            if hidxs[n - 1].hval != tmp:
              break
            n -= 1
          return n + 1
        else:
          return 0
      n += 1
    else:
      i = step + 1
      step = min (step >> 2, <size_t>512 // sizeof (hidxs[0]))
      while step > 0:
        tmp = hidxs[i].hval
        if tmp < hval:
          step -= 1
          i += 1
        elif tmp == hval:
          while i > 0:
            if hidxs[i - 1].hval != tmp:
              break
            i -= 1
          return i + 1
        else:
          return 0
  return 0

cdef size_t _find_obj_by_hidx (hidx_type hidxs, size_t ix, size_t n,
                               obj, proxy_list indices):
  cdef size_t hval
  cdef unsigned long long data

  if ix == 0:
    return ix

  ix -= 1
  hval = hidxs[ix].hval

  while 1:
    data = hidxs[ix].key_off
    key = indices.proxy._unpack_with_data (data, indices)

    ix += 1
    if obj == key:
      return ix
    elif ix == n or hidxs[ix].hval != hval:
      return 0

################################
# Functions on sets.

cdef inline bint _cnum_lt (cnum x, cnum y):
  if cnum is double:
    return _double_diff (x, y) < 0
  else:
    return x < y

cdef object _cnum_set_union (const void *p1, size_t l1, const void *p2,
                             size_t l2, set out, cnum elem):
  cdef size_t i, j

  i = j = 0
  while i < l1:
    if j == l2:
      while i < l1:
        out.add ((<const cnum *>p1)[i])
        i += 1
      return
    elif _cnum_lt ((<const cnum *>p2)[j], (<const cnum *>p1)[i]):
      out.add ((<const cnum *>p2)[j])
      j += 1
    else:
      out.add ((<const cnum *>p1)[i])
      if _cnum_lt ((<const cnum *>p1)[i], (<const cnum *>p2)[j]):
        j += 1
      i += 1

  while j < l2:
    out.add ((<const cnum *>p2)[j])
    j += 1

cdef object _cnum_set_intersection (const void *p1, size_t l1, const void *p2, 
                                    size_t l2, set out, cnum elem):
  cdef size_t i, j

  i = j = 0
  while i < l1 and j < l2:
    if _cnum_lt ((<const cnum *>p1)[i], (<const cnum *>p2)[j]):
      i += 1
    else:
      if not _cnum_lt ((<const cnum *>p2)[j], (<const cnum *>p1)[i]):
        out.add ((<const cnum *>p1)[i])
      j += 1

cdef object _cnum_set_difference (const void *p1, size_t l1, const void *p2, 
                                  size_t l2, set out, cnum elem):
  cdef size_t i, j

  i = j = 0
  while i < l1:
    if j == l2:
      while i < l1:
        out.add ((<const cnum *>p1)[i])
        i += 1
      return
    elif _cnum_lt ((<const cnum *>p1)[i], (<const cnum *>p2)[j]):
      out.add ((<const cnum *>p1)[i])
      i += 1
    else:
      if not _cnum_lt ((<const cnum *>p2)[j], (<const cnum *>p1)[i]):
        i += 1
      j += 1

cdef object _cnum_set_symdiff (const void *p1, size_t l1, const void *p2,
                               size_t l2, set out, cnum elem):
  cdef size_t i, j

  i = j = 0
  while i < l1:
    if j == l2:
      while i < l1:
        out.add ((<const cnum *>p1)[i])
        i += 1
      return
    elif _cnum_lt ((<const cnum *>p1)[i], (<const cnum *>p2)[j]):
      out.add ((<const cnum *>p1)[i])
      i += 1
    else:
      if _cnum_lt ((<const cnum *>p2)[j], (<const cnum *>p1)[i]):
        out.add ((<const cnum *>p2)[j])
      else:
        i += 1
      j += 1

  while j < l2:
    out.add ((<const cnum *>p2)[j])
    j += 1

cdef bint _cnum_set_includes (const void *p1, size_t l1, const void *p2,
                              size_t l2, cnum elem):
  cdef size_t i, j

  if l1 == l2:
    return memcmp (p1, p2, l1 * sizeof (elem)) == 0

  i = j = 0
  while j < l2:
    if i == l1 or _cnum_lt ((<const cnum *>p2)[j], (<const cnum *>p1)[i]):
      return 0
    elif not _cnum_lt ((<const cnum *>p1)[i], (<const cnum *>p2)[j]):
      j += 1
    i += 1

  return 1

cdef class proxy_set:
  cdef proxy_list indices

  @staticmethod
  cdef proxy_set _make (proxy_handler proxy, size_t offset):
    cdef proxy_set self

    self = proxy_set.__new__ (proxy_set)
    self.indices = proxy_list._make (proxy, offset, False)
    if self.indices.code > tpcode.FLOAT:
      self.indices.size >>= 1
    return self

  def __len__ (self):
    return self.indices.size

  @cy.final
  cdef set _union (self, proxy_set pset):
    cdef proxy_list ix1, ix2
    cdef const unsigned char *p1
    cdef const unsigned char *p2
    cdef set out

    ix1, ix2 = self.indices, pset.indices
    if ix1.code == ix2.code and ix1.code <= tpcode.FLOAT:
      out = set ()
      p1 = <const unsigned char *> (ix1.proxy.base + ix1.offset)
      p2 = <const unsigned char *> (ix2.proxy.base + ix2.offset)

      if ix1.code == tpcode.INT:
        _cnum_set_union[Py_ssize_t] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.UINT:
        _cnum_set_union[size_t] (p1, ix1.size, p2, ix2.size, out, 0)
      else:
        _cnum_set_union[double] (p1, ix1.size, p2, ix2.size, out, 0)
      return out
    else:
      return set(self).union (pset)

  @cy.final
  cdef set _intersection (self, proxy_set pset):
    cdef proxy_list ix1, ix2
    cdef const unsigned char *p1
    cdef const unsigned char *p2
    cdef set out

    ix1, ix2 = self.indices, pset.indices
    if ix1.code == ix2.code and ix1.code <= tpcode.FLOAT:
      out = set ()
      p1 = <const unsigned char *> (ix1.proxy.base + ix1.offset)
      p2 = <const unsigned char *> (ix2.proxy.base + ix2.offset)

      if ix1.code == tpcode.INT:
        _cnum_set_intersection[Py_ssize_t] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.UINT:
        _cnum_set_intersection[size_t] (p1, ix1.size, p2, ix2.size, out, 0)
      else:
        _cnum_set_intersection[double] (p1, ix1.size, p2, ix2.size, out, 0)
      return out
    else:
      return set(self).intersection (pset)

  @cy.final
  cdef set _difference (self, proxy_set pset):
    cdef proxy_list ix1, ix2
    cdef const unsigned char *p1
    cdef const unsigned char *p2
    cdef set out

    ix1, ix2 = self.indices, pset.indices
    if ix1.code == ix2.code and ix1.code <= tpcode.FLOAT:
      out = set ()
      p1 = <const unsigned char *> (ix1.proxy.base + ix1.offset)
      p2 = <const unsigned char *> (ix2.proxy.base + ix2.offset)

      if ix1.code == tpcode.INT:
        _cnum_set_difference[Py_ssize_t] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.UINT:
        _cnum_set_difference[size_t] (p1, ix1.size, p2, ix2.size, out, 0)
      else:
        _cnum_set_difference[double] (p1, ix1.size, p2, ix2.size, out, 0)
      return out
    else:
      return set(self).difference (pset)

  @cy.final
  cdef set _symdiff (self, proxy_set pset):
    cdef proxy_list ix1, ix2
    cdef const unsigned char *p1
    cdef const unsigned char *p2
    cdef set out

    ix1, ix2 = self.indices, pset.indices
    if ix1.code == ix2.code and ix1.code <= tpcode.FLOAT:
      out = set ()
      p1 = <const unsigned char *> (ix1.proxy.base + ix1.offset)
      p2 = <const unsigned char *> (ix2.proxy.base + ix2.offset)

      if ix1.code == tpcode.INT:
        _cnum_set_symdiff[Py_ssize_t] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.UINT:
        _cnum_set_symdiff[size_t] (p1, ix1.size, p2, ix2.size, out, 0)
      else:
        _cnum_set_symdiff[double] (p1, ix1.size, p2, ix2.size, out, 0)
      return out
    else:
      return set(self).symmetric_difference (pset)

  def __contains__ (self, value):
    cdef proxy_list indices
    cdef proxy_handler proxy
    cdef unsigned int code
    cdef size_t n, ix
    cdef const array_2I *iarray
    cdef const array_2Q *qarray
    cdef const unsigned char *ptr

    indices = self.indices
    proxy = indices.proxy
    code = indices.code
    n = indices.size
    ptr = <const unsigned char *> (proxy.base + indices.offset)

    if code == tpcode.INT:
      return _cnum_find_sorted[Py_ssize_t] (ptr, n, value, 0, 0)
    elif code == tpcode.UINT:
      return _cnum_find_sorted[size_t] (ptr, n, value, 0, 0)
    elif code == tpcode.FLOAT:
      return _cnum_find_sorted[double] (ptr, n, value, 0, 0)
    elif code == b"I":
      iarray = <const array_2I *>ptr
      ix = _find_hidx (iarray, _xhash (value, proxy.hash_seed), n)
      return _find_obj_by_hidx (iarray, ix, n, value, indices) != 0
    else:
      qarray = <const array_2Q *>ptr
      ix = _find_hidx (qarray, _xhash (value, proxy.hash_seed), n)
      return _find_obj_by_hidx (qarray, ix, n, value, indices) != 0

  def __iter__ (self):
    cdef unsigned int code
    cdef char *ptr
    cdef unsigned long long data
    cdef size_t i

    code = self.indices.code
    ptr = self.indices.proxy.base + self.indices.offset

    for i in range (self.indices.size):
      if code == tpcode.INT:
        yield (<Py_ssize_t *>ptr)[i]
      elif code == tpcode.UINT:
        yield (<size_t *>ptr)[i]
      elif code == tpcode.FLOAT:
        yield (<double *>ptr)[i]
      else:
        if code == b"I":
          data = (<const array_2I *>ptr)[i].key_off
        else:
          data = (<const array_2Q *>ptr)[i].key_off

        yield self.indices.proxy._unpack_with_data (data, self.indices)

  def union (self, *args):
    if not args:
      return self
    elif len (args) == 1:
      tmp = args[0]
      if isinstance (tmp, proxy_set):
        return self._union (<proxy_set>tmp)
    return set(self).union (*args)

  def intersection (self, *args):
    if not args:
      return self
    elif len (args) == 1:
      tmp = args[0]
      if isinstance (tmp, proxy_set):
        return self._intersection (<proxy_set>tmp)
    return set(self).intersection (*args)

  def difference (self, *args):
    if not args:
      return self
    elif len (args) == 1:
      tmp = args[0]
      if isinstance (tmp, proxy_set):
        return self._difference (<proxy_set>tmp)
    return set(self).difference (*args)

  def symmetric_difference (self, *args):
    if not args:
      return self
    elif len (args) == 1:
      tmp = args[0]
      if isinstance (tmp, proxy_set):
        return self._symdiff (<proxy_set>tmp)
    return set(self).symmetric_difference (*args)

  def __and__ (self, x):
    cdef proxy_set this

    if isinstance (self, proxy_set):
      this = <proxy_set>self
      if isinstance (x, proxy_set):
        return this._intersection (<proxy_set>x)
      return set(this).intersection (x)
    elif not isinstance (self, (set, frozenset)):
      raise TypeError ("cannot compute intersection between %r and %r" %
                       (type(self).__name__, type(x).__name__))
    return self.intersection (set (x))

  def __or__ (self, x):
    cdef proxy_set this

    if isinstance (self, proxy_set):
      this = <proxy_set>self
      if isinstance (x, proxy_set):
        return this._union (<proxy_set>x)
      return set(this).union (x)
    elif not isinstance (self, (set, frozenset)):
      raise TypeError ("cannot compute union between %r and %r" %
                       (type(self).__name__, type(x).__name__))
    return self.union (set (x))

  def __sub__ (self, x):
    cdef proxy_set this

    if isinstance (self, proxy_set):
      this = <proxy_set>self
      if isinstance (x, proxy_set):
        return this._difference (<proxy_set>x)
      return set(this).difference (x)
    elif not isinstance (self, (set, frozenset)):
      raise TypeError ("cannot compute difference between %r and %r" %
                       (type(self).__name__, type(x).__name__))
    return self.difference (set (x))

  def __xor__ (self, x):
    cdef proxy_set this

    if isinstance (self, proxy_set):
      this = <proxy_set>self
      if isinstance (x, proxy_set):
        return this._symdiff (<proxy_set>x)
      return set(this).symmetric_difference (x)
    elif not isinstance (self, (set, frozenset)):
      raise TypeError ("cannot compute symmetric difference between %r and %r" %
                       (type(self).__name__, type(x).__name__))
    return self.symmetric_difference (set (x))

  cdef bint _eq (self, x):
    cdef proxy_set ps
    cdef proxy_list ix1, ix2

    if (self.indices.code <= tpcode.FLOAT and isinstance (x, proxy_set) and
        (<proxy_set>x).indices.code == self.indices.code):
      ps = <proxy_set>x
      ix1, ix2 = self.indices, ps.indices
      return (ps.indices.size == self.indices.size and
              memcmp (ix1.proxy.base + ix1.offset, ix2.proxy.base + ix2.offset,
                      ix1.size * sizeof (size_t)) == 0)

    if not isinstance (x, (set, frozenset, proxy_set)) or len (x) != len (self):
      return False
    for elem in self:
      if elem not in x:
        return False
    return True

  def __eq__ (self, x):
    if isinstance (self, proxy_set):
      return (<proxy_set>self)._eq (x)
    return (<proxy_set>x)._eq (self)

  cdef bint _subset (self, x, bint lt):
    cdef bint ret
    cdef proxy_list ix1, ix2
    cdef const void *p1
    cdef const void *p2

    if (self.indices.code <= tpcode.FLOAT and
        isinstance (x, proxy_set) and
        (<proxy_set>x).indices.code == self.indices.code):
      ix1, ix2 = self.indices, (<proxy_set>x).indices
      p1 = <const void *> (ix1.proxy.base + ix1.offset)
      p2 = <const void *> (ix2.proxy.base + ix2.offset)

      if ix1.size > ix2.size:
        ret = False
      elif self.indices.code == tpcode.INT:
        ret = _cnum_set_includes[Py_ssize_t] (p2, ix2.size, p1, ix1.size, 0)
      elif self.indices.code == tpcode.UINT:
        ret = _cnum_set_includes[size_t] (p2, ix2.size, p1, ix1.size, 0)
      else:
        ret = _cnum_set_includes[double] (p2, ix2.size, p1, ix1.size, 0)

      if lt:
        ret = ret and ix1.size < ix2.size

    elif (not isinstance (x, (set, frozenset, proxy_set)) or
          len (self) > len (x)):
      ret = False
    else:
      ret = True
      for elem in self:
        if elem not in x:
          ret = False
          break

      if ret and lt:
        ret = len (self) < len (x)

    return ret

  def __lt__ (self, x):
    if isinstance (self, proxy_set):
      return (<proxy_set>self)._subset (x, True)
    return (<proxy_set>x)._subset (self, True)

  def __le__ (self, x):
    if isinstance (self, proxy_set):
      return (<proxy_set>self)._subset (x, False)
    return (<proxy_set>x)._subset (self, False)

  def __gt__ (self, x):
    return x < self

  def __ge__ (self, x):
    return x <= self

  def __str__ (self):
    return "{%s}" % ",".join ([str (x) for x in self])

  def __repr__ (self):
    return "proxy_set(%s)" % self

  @cy.final
  cdef _toset (self):
    rv = set ()
    unproxy_ = unproxy
    for elem in self:
      rv.add (unproxy_ (elem))
    return rv

########################################

cdef inline object _proxy_dict_iter_key (hidx_type hidxs, size_t ix, iobj):
  cdef proxy_list indices

  indices = <proxy_list>iobj
  return indices.proxy._unpack_with_data (hidxs[ix].key_off, indices)

cdef inline object _proxy_dict_iter_val (hidx_type hidxs, size_t ix, iobj):
  cdef proxy_list indices

  indices = <proxy_list>iobj
  return indices.proxy._unpack_with_data (hidxs[ix].val_off, indices)

cdef inline object _proxy_dict_iter_both (hidx_type hidxs, size_t ix, iobj):
  cdef proxy_list indices

  indices = <proxy_list>iobj
  return (indices.proxy._unpack_with_data (hidxs[ix].key_off, indices),
          indices.proxy._unpack_with_data (hidxs[ix].val_off, indices))

cdef class proxy_dict:
  cdef proxy_list indices

  @staticmethod
  cdef proxy_dict _make (proxy_handler proxy, size_t offset):
    cdef proxy_dict self

    self = proxy_dict.__new__ (proxy_dict)
    self.indices = proxy_list._make (proxy, offset, False)
    self.indices.size //= 3
    return self

  def __len__ (self):
    return self.indices.size

  @cy.final
  cdef object _c_get (self, key, dfl):
    cdef proxy_list indices
    cdef proxy_handler proxy
    cdef size_t n, ix
    cdef const array_3I *iarray
    cdef const array_3Q *qarray

    indices = self.indices
    proxy = indices.proxy
    n = indices.size

    if indices.code == b"I":
      iarray = <const array_3I *> (proxy.base + indices.offset)
      ix = _find_hidx (iarray, _xhash (key, proxy.hash_seed), n)
      ix = _find_obj_by_hidx (iarray, ix, n, key, indices)
      if ix != 0:
        return proxy._unpack_with_data (iarray[ix - 1].val_off, indices)
    else:
      qarray = <const array_3Q *> (proxy.base + indices.offset)
      ix = _find_hidx (qarray, _xhash (key, proxy.hash_seed), n)
      ix = _find_obj_by_hidx (qarray, ix, n, key, indices)
      if ix != 0:
        return proxy._unpack_with_data (qarray[ix - 1].val_off, indices)

    return dfl

  def __contains__ (self, key):
    return self._c_get (key, _SENTINEL) is not _SENTINEL
  
  def __getitem__ (self, key):
    ret = self._c_get (key, _SENTINEL)
    if ret is _SENTINEL:
      raise KeyError (key)
    return ret

  def get (self, key, dfl = None):
    return self._c_get (key, dfl)

  def _iter_impl (self, size_t wfn):
    cdef dict_iter_fn fn
    cdef size_t i
    cdef proxy_list indices

    indices = self.indices
    fn = fn_caster(wfn).bfn

    for i in range (indices.size):
      yield fn (indices.proxy.base + indices.offset, i, indices)

  def keys (self):
    cdef fn_caster caster

    if self.indices.code == b"I":
      caster.bfn = <dict_iter_fn>_proxy_dict_iter_key["const array_3I*"]
    else:
      caster.bfn = <dict_iter_fn>_proxy_dict_iter_key["const array_3Q*"]
    return self._iter_impl (caster.wfn)

  def values (self):
    cdef fn_caster caster

    if self.indices.code == b"I":
      caster.bfn = <dict_iter_fn>_proxy_dict_iter_val["const array_3I*"]
    else:
      caster.bfn = <dict_iter_fn>_proxy_dict_iter_val["const array_3Q*"]
    return self._iter_impl (caster.wfn)

  def items (self):
    cdef fn_caster caster

    if self.indices.code == b"I":
      caster.bfn = <dict_iter_fn>_proxy_dict_iter_both["const array_3I*"]
    else:
      caster.bfn = <dict_iter_fn>_proxy_dict_iter_both["const array_3Q*"]
    return self._iter_impl (caster.wfn)

  @cy.final
  cdef _todict (self):
    cdef dict_iter_fn kget, vget
    cdef proxy_list indices
    cdef void *ptr

    rv = {}
    unproxy_ = unproxy
    if self.indices.code == b"I":
      kget = <dict_iter_fn>_proxy_dict_iter_key["const array_3I*"]
      vget = <dict_iter_fn>_proxy_dict_iter_val["const array_3I*"]
    else:
      kget = <dict_iter_fn>_proxy_dict_iter_key["const array_3Q*"]
      vget = <dict_iter_fn>_proxy_dict_iter_val["const array_3Q*"]

    indices = self.indices
    ptr = indices.proxy.base + indices.offset
    for i in range (indices.size):
      key = kget (ptr, i, indices)
      val = vget (ptr, i, indices)
      rv[unproxy_ (key)] = unproxy_ (val)

    return rv

  def __iter__ (self):
    return self.keys ()

  def copy (self):
    return dict (self.items ())

  def __eq__ (self, other):
    try:
      if len (self) != len (other):
        return False
      for key, val in self.items ():
        if key not in other or other[key] != val:
          return False
      return True
    except (KeyError, IndexError):
      return False

  def __str__ (self):
    return "{%s}" % ", ".join (["%r: %r" % (k, v) for k, v in self.items ()])

  def __repr__ (self):
    return "proxy_dict(%s)" % self

#####################################

cdef inline cnum _descr_get_cnum (proxy_handler proxy,
                                  size_t offset, cnum elem):
  if proxy.rdwr:
    atomic_fence ()
  return (<const cnum *> (proxy.base + offset))[0]

cdef inline _descr_set_cnum (proxy_handler proxy,
                             size_t offset, cnum value):
  if not proxy.rdwr:
    raise TypeError ("cannot modify attribute of read-only object")
  (<cnum *> (proxy.base + offset))[0] = value
  atomic_fence ()

cdef class proxy_descr_int:
  cdef size_t offset
  cdef proxy_handler proxy

  @staticmethod
  cdef proxy_descr_int _make (size_t offset, proxy_handler proxy):
    cdef proxy_descr_int ret

    ret = proxy_descr_int.__new__ (proxy_descr_int)
    ret.offset = offset + _get_padding (offset, sizeof (Py_ssize_t))
    ret.proxy = proxy
    ret.proxy._assert_len (ret.offset + sizeof (Py_ssize_t))
    return ret

  def __get__ (self, obj, cls):
    if obj is None:
      return self

    return _descr_get_cnum[Py_ssize_t] (self.proxy, self.offset, 0)

  def __set__ (self, obj, value):
    _descr_set_cnum[Py_ssize_t] (self.proxy, self.offset, value)

  def add (self, value):
    if not self.proxy.rdwr:
      raise TypeError ("cannot modify attribute of read-only object")
    return atomic_add_i (self.proxy.base + self.offset, value)

  def cas (self, exp, nval):
    if not self.proxy.rdwr:
      raise TypeError ("cannot modify attribute of read-only object")
    if atomic_cas_i (self.proxy.base + self.offset, exp, nval) == 1:
      return True
    return False

cdef class proxy_descr_uint:
  cdef size_t offset
  cdef proxy_handler proxy

  @staticmethod
  cdef proxy_descr_uint _make (size_t offset, proxy_handler proxy):
    cdef proxy_descr_uint ret

    ret = proxy_descr_uint.__new__ (proxy_descr_uint)
    ret.offset = offset + _get_padding (offset, sizeof (size_t))
    ret.proxy = proxy
    ret.proxy._assert_len (ret.offset + sizeof (size_t))
    return ret

  def __get__ (self, obj, cls):
    if obj is None:
      return self

    return _descr_get_cnum[size_t] (self.proxy, self.offset, 0)

  def __set__ (self, obj, value):
    _descr_set_cnum[size_t] (self.proxy, self.offset, value)

  def add (self, value):
    if not self.proxy.rdwr:
      raise TypeError ("cannot modify attribute of read-only object")
    return atomic_add_I (self.proxy.base + self.offset, value)

  def cas (self, exp, nval):
    if not self.proxy.rdwr:
      raise TypeError ("cannot modify attribute of read-only object")
    if atomic_cas_I (self.proxy.base + self.offset, exp, nval) == 1:
      return True
    return False

cdef class proxy_descr_float:
  cdef size_t offset
  cdef proxy_handler proxy

  @staticmethod
  cdef proxy_descr_float _make (size_t offset, proxy_handler proxy):
    cdef proxy_descr_float ret

    ret = proxy_descr_float.__new__ (proxy_descr_float)
    ret.offset = offset + _get_padding (offset, sizeof (double))
    ret.proxy = proxy
    ret.proxy._assert_len (ret.offset + sizeof (double))
    return ret

  def __get__ (self, obj, cls):
    if obj is None:
      return self

    return _descr_get_cnum[double] (self.proxy, self.offset, 0)

  def __set__ (self, obj, value):
    _descr_set_cnum[double] (self.proxy, self.offset, value)

  def add (self, value):
    if not self.proxy.rdwr:
      raise TypeError ("cannot modify attribute of read-only object")

    return atomic_add_f (self.proxy.base + self.offset, value)

  def cas (self, exp, nval):
    if not self.proxy.rdwr:
      raise TypeError ("cannot modify attribute of read-only object")
    if atomic_cas_f (self.proxy.base + self.offset, exp, nval) == 1:
      return True
    return False

cdef class proxy_descr_any:
  cdef unsigned long long data
  cdef proxy_handler proxy

  @staticmethod
  cdef proxy_descr_any _make (unsigned long long data, proxy_handler proxy):
    cdef proxy_descr_any ret

    ret = proxy_descr_any.__new__ (proxy_descr_any)
    ret.data = data
    ret.proxy = proxy
    return ret

  def __get__ (self, obj, cls):
    if obj is None:
      return self

    return self.proxy._unpack_with_code (self.data >> 5, self.data & 0x1f)

cdef object _make_descr (proxy_handler proxy, size_t base,
                         unsigned long long data):
  cdef unsigned int code

  code = data & 0x1f
  if code == tpcode.INT:
    return proxy_descr_int._make (base + (data >> 5), proxy)
  elif code == tpcode.UINT:
    return proxy_descr_uint._make (base + (data >> 5), proxy)
  elif code == tpcode.FLOAT:
    return proxy_descr_float._make (base + (data >> 5), proxy)
  else:
    data = ((base + (data >> 5)) << 5) | code
    return proxy_descr_any._make (data, proxy)

cdef inline str _decode_str (proxy_handler proxy, size_t off, size_t size):
  proxy._assert_len (off + size)
  return PyUnicode_FromStringAndSize (proxy.base + off, size)

cdef object _read_type (proxy_handler proxy, size_t *offp):
  cdef size_t off, size
  cdef str path, md
  cdef unsigned int md_len
  cdef Py_ssize_t ix

  off = offp[0]
  if proxy.import_key is not None:
    proxy._assert_len (off + sizeof (md_len))
    memcpy (&md_len, proxy.base + off, sizeof (md_len))
    md = _decode_str (proxy, off + sizeof (md_len), md_len)
    off += md_len + sizeof (md_len)

  size = proxy[off]
  if size == 0xff:
    proxy._assert_len (off + 1 + sizeof (size_t))
    memcpy (&size, proxy.base + off + 1, sizeof (size))
    off += sizeof (size)

  off += 1
  path = _decode_str (proxy, off, size)

  ix = path.rfind (".")
  if ix < 0:
    raise ValueError ("got an invalid typename %r" % path)
  elif (proxy.import_key is not None and
      md != HMAC(proxy.import_key, _encode_str (path),
                 _HASH_METHOD).hexdigest ()):
    raise ValueError ("import signature mismatch")

  typ = getattr (Import_Module (path[:ix]), path[ix + 1:])
  offp[0] = off + size
  return typ

cdef object _proxy_obj (proxy_handler proxy, size_t off):
  cdef unsigned int wide, i_size, klen
  cdef size_t base, i, saved, size
  cdef void *ptr
  cdef unsigned int *ioffs
  cdef unsigned long long *qoffs
  cdef str name

  typ = _read_type (proxy, &off)
  off += _get_padding (off, sizeof (long long))

  proxy._assert_len (off + 2 * sizeof (int))
  i_size = (<unsigned int *> (proxy.base + off))[0]
  klen = (<unsigned int *> (proxy.base + off))[1]
  wide = i_size & 1
  i_size >>= 1
  base = off + sizeof (int) * 2
  ptr = proxy.base + base
  base += i_size * (sizeof (unsigned int) << wide)
  proxy._assert_len (base)

  descrs = {}
  saved = base + klen + _get_padding (base + klen, sizeof (long long))

  if wide:
    qoffs = <unsigned long long *>ptr
    for i in range (0, i_size, 2):
      name = _decode_str (proxy, base, qoffs[i])
      descrs[name] = _make_descr (proxy, saved, qoffs[i + 1])
      base += qoffs[i]
  else:
    ioffs = <unsigned int *>ptr
    for i in range (0, i_size, 2):
      name = _decode_str (proxy, base, ioffs[i])
      descrs[name] = _make_descr (proxy, saved, ioffs[i + 1])
      base += ioffs[i]

  typ = type ("proxy_object", (typ,), descrs)
  return typ.__new__ (typ)

def _register_impl (typ, ix, fn):
  if type (typ) is not type:
    raise ValueError ("expected a type")
  with _custom_packers_lock as _:
    flist = _custom_packers.get (typ)
    if flist:
      flist[ix] = fn
    else:
      flist = [None, None]
      flist[ix] = fn
      _custom_packers[typ] = flist
  return fn

def register_pack (typ):
  """
  Decorator used to register a packing function for the specified type.
  """
  return partial (_register_impl, typ, direction.PACK)

def register_unpack (typ):
  """
  Decorator used to register an unpacking function for the specified type.
  """
  return partial (_register_impl, typ, direction.UNPACK)

cdef object _dispatch_type_impl (dict packers, typ, unsigned int ix):
  cdef list flist, val
  cdef Py_ssize_t dist

  flist = packers.get (typ)
  if flist:
    rv = flist[ix]
    if rv:
      return rv

  dist = _MAX_DISTANCE
  fn = None

  for key, val in _custom_packers.items ():
    try:
      if key.__mro__.index (typ) < dist:
        fn = val[ix]
        if fn is not None:
          dist = ix
    except ValueError:
      pass

  return fn

cdef object _dispatch_type (typ, unsigned int ix):
  with _custom_packers_lock as _:
    return _dispatch_type_impl (_custom_packers, typ, ix)

def pack (obj, **kwargs):
  """
  Return a bytearray with the serialized representation of ``obj``.
  The keyword arguments are the same as those used in ``packer.__init__``.
  """
  cdef packer p

  p = packer (**kwargs)
  p.pack (obj)
  return p.as_bytearray ()

def pack_into (obj, place, offset = None, **kwargs):
  """
  Pack an object at a specific offset in a destination.

  :param obj: The object to be serialized.

  :param place: The object in which to serialize it. This object may be
    a bytearray, or any object that implements the methods ``write``, and
    ``seek`` (in case the specified offset is not None).

  :param offset *(default None)*: The offset at which to serialize the object.
    If None, the object will be serialized at the destination's current
    position, if it applies.

  See ``packer.__init__`` for information about the supported keyword args.
  """
  cdef bytearray b, bp

  b = pack (obj, offset = offset or 0, **kwargs)
  fn = getattr (place, "write", _SENTINEL)
  if fn is not _SENTINEL:
    if offset is None:
      return fn (b)
    else:
      seek = getattr (place, "seek", _SENTINEL)
      if seek is _SENTINEL:
        raise ValueError (
          "don't know how to pack into object of type %r at a specific offset" %
          type(place).__name__
        )

      prev = seek (0, 1)
      seek (offset, 0)

      mv = memoryview (b)
      ioff = offset & (sizeof (long long) - 1)
      ret = fn (mv[ioff:])
      seek (prev, 0)
      return ret
  elif isinstance (place, bytearray):
    bp = <bytearray>place
    if offset is None:
      bp.extend (b)
    else:
      mv = memoryview (b)
      ioff = offset & (sizeof (long long) - 1)
      bp[offset:len(mv) - offset] = mv[ioff:]
    return len (b)
  else:
    raise TypeError ("don't know how to pack into object of type %r" %
                     type(place).__name__)

def unpack_from (place, offset = 0, **kwargs):
  """
  Unpack an object from an input source from a specified object.

  :param place: The source object from which to unpack. Can be any object
    with which a ``proxy_handler`` can be built.

  :param int offset *(default 0)*: The offset inside the source at which
    to unpack.

  See ``proxy_handler.__init__`` for information about the supported
    keyword args.
  """
  return proxy_handler(place, offset, **kwargs).unpack ()

def unpack_as (place, code, offset = 0, **kwargs):
  """
  Unpack an object from an input source using a specific type and offset.

  :param place: The source object from which to unpack. Can be any object
    with which a ``proxy_handler`` can be built.

  :param int code: The typecode of the object to unpack. Must be one of
    the TYPE_* constants defined in this module.

  :param int offset *(default 0)*: The offset inside the source at which
    to unpack.

  See ``proxy_handler.__init__`` for information about the supported
    keyword args.
  """
  return proxy_handler(place, 0, **kwargs).unpack_as (code, offset)

def unproxy (obj):
  """
  Convert any proxied object into its materialized counterpart, recursively.
  i.e: a proxy_list is turned into a regular Python list.
  """
  if isinstance (obj, proxy_str):
    return _PyUnicode_Copy ((<proxy_str>obj).uobj)
  elif isinstance (obj, proxy_set):
    return (<proxy_set>obj)._toset ()
  elif isinstance (obj, proxy_dict):
    return (<proxy_dict>obj)._todict ()
  elif isinstance (obj, proxy_list):
    return (<proxy_list>obj)._unproxy ()
  return obj

# Exported typecodes for the 'unpack_as' functions.
TYPE_INT = tpcode.INT
TYPE_UINT = tpcode.UINT
TYPE_FLOAT = tpcode.FLOAT
TYPE_BIGINT = tpcode.NUM
TYPE_STR = tpcode.STR
TYPE_BYTES = tpcode.BYTES
TYPE_BYTEARRAY = tpcode.BYTEARRAY
TYPE_LIST = tpcode.LIST
TYPE_TUPLE = tpcode.TUPLE
TYPE_NONE = tpcode.NONE
TYPE_TRUE = tpcode.TRUE
TYPE_FALSE = tpcode.FALSE
TYPE_SET = tpcode.SET
TYPE_DICT = tpcode.DICT
TYPE_BACKREF = tpcode.BACKREF
TYPE_OBJECT = tpcode.OTHER
