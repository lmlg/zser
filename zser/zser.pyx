 # Copyright (c) 2025 Luciano Lo Giudice
 # Copyright (c) 2025 Agustina Arzille.
 #
 # This program is free software: you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation, either version 3 of the License, or
 # (at your option) any later version.
 #
 # This program is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 # GNU General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this program.  If not, see <http://www.gnu.org/licenses/>.

cimport cython as cy
from functools import partial as _partial
from importlib import import_module
from itertools import chain
import hashlib
import hmac
from io import StringIO
import mmap
import operator
import struct
from sys import byteorder, maxsize
from threading import Lock
import types

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
cdef object Int_From_Bytes = int.from_bytes

cdef object Import_Module = import_module

cdef dict _custom_packers = {}
cdef object _custom_packers_lock = Lock ()

cdef object HMAC = hmac.HMAC
cdef object _HASH_METHOD = hashlib.sha256

# These must be kept in sync with the typecodes.
cdef tuple _BASIC_FMTS = ("b", "h", "i", "l", "f", "d")
cdef size_t[6] _BASIC_SIZES = [sizeof (char), sizeof (short),
                               sizeof (int), sizeof (long long),
                               sizeof (float), sizeof (double)]

cdef bint _IS_64_BIT = maxsize > 4294967296

# Basic types that may be stored inline in lists, sets, dicts and descriptors.
ctypedef fused cnum:
  signed char
  unsigned char
  short
  unsigned short
  int
  unsigned int
  long long
  unsigned long long
  float
  double

# Basic floating point types. Also declared here as a workaround for atomic
# operations, which need special implementations for them.
ctypedef fused cfloat:
  float
  double

hidx_type = cy.fused_type ("const unsigned int *", "const unsigned long long *")

# Special object used for detecting misses in dict lookups.
cdef object _SENTINEL = object ()

# Map used to fixup type names that aren't exported in the 'builtins' module.
cdef dict _BUILTINS_MAP = {
  'ellipsis': types.EllipsisType,
  'module': types.ModuleType,
  'function': types.FunctionType,
  'builtin_function_or_method': types.BuiltinFunctionType
}

cdef inline bint _is_inline_code (unsigned int code):
  return code <= tpcode.FLOAT64

cdef inline size_t _get_padding (size_t off, size_t size):
  return ((off + size) & ~(size - 1)) - off

cdef _pack_cnum (Packer xm, int code, cnum value):
  cdef size_t offset, extra, rv
  cdef char *ptr

  offset = xm.offset
  extra = _get_padding (offset + 1, sizeof (value))
  rv = extra + sizeof (value) + 1
  xm.resize (rv)
  ptr = xm.ptr
  extra += offset + 1

  ptr[offset] = code
  (<cnum *> (ptr + extra))[0] = value
  xm.bump (rv)

def _pack_int (Packer xm, value):
  if INT8_MIN <= value <= INT8_MAX:
    _pack_cnum[cy.schar] (xm, tpcode.INT8, value)
  elif INT16_MIN <= value <= INT16_MAX:
    _pack_cnum[short] (xm, tpcode.INT16, value)
  elif INT32_MIN <= value <= INT32_MAX:
    _pack_cnum[int] (xm, tpcode.INT32, value)
  elif _IS_64_BIT and (INT64_MIN <= value <= INT64_MAX):
    _pack_cnum[cy.longlong] (xm, tpcode.INT64, value)
  else:
    # Bigint.
    bitlen = value.bit_length ()
    rlen = bitlen // 8 + 1
    brepr = value.to_bytes (rlen, SYS_endian, signed = True)
    xm.putb (tpcode.NUM)
    blen = len (brepr)
    xm.pack_struct ("=I" + str (blen) + "s", blen, brepr)

cdef class i8:
  cdef cy.schar value

  def __init__ (self, val):
    self.value = val

  def pack (self, Packer xm):
    _pack_cnum[cy.schar] (xm, tpcode.INT8, self.value)

cdef class i16:
  cdef short value

  def __init__ (self, val):
    self.value = val

  def pack (self, Packer xm):
    _pack_cnum[short] (xm, tpcode.INT16, self.value)

cdef class i32:
  cdef int value

  def __init__ (self, val):
    self.value = val

  def pack (self, Packer xm):
    _pack_cnum[int] (xm, tpcode.INT32, self.value)

cdef class i64:
  cdef cy.longlong value

  def __init__ (self, val):
    self.value = val

  def pack (self, Packer xm):
    _pack_cnum[cy.longlong] (xm, tpcode.INT64, self.value)

cdef int _float_code (obj):
  cdef double dbl

  if FLOAT32_MIN <= obj <= FLOAT32_MAX:
    dbl = obj
    # Only use FLOAT32 if we're certain no precision loss takes place.
    if <float>dbl == dbl:
      return tpcode.FLOAT32
  return tpcode.FLOAT64

def _pack_float (Packer xm, value):
  if _float_code (value) == tpcode.FLOAT32:
    _pack_cnum[float] (xm, tpcode.FLOAT32, value)
  else:
    _pack_cnum[double] (xm, tpcode.FLOAT64, value)

cdef class f32:
  cdef float value

  def __init__ (self, val):
    self.value = val

  def pack (self, Packer xm):
    _pack_cnum[float] (xm, tpcode.FLOAT32, self.value)

cdef class f64:
  cdef double value

  def __init__ (self, val):
    self.value = val

  def pack (self, Packer xm):
    _pack_cnum[double] (xm, tpcode.FLOAT64, self.value)

cdef size_t _write_uleb128 (void *buf, size_t off, size_t val):
  cdef unsigned char byte
  cdef unsigned char *outp
  cdef unsigned char *start
  cdef size_t ret

  start = <unsigned char *>buf
  outp = start = start + off

  while True:
    byte = <unsigned char> (val & 0x7f)
    val >>= 7

    if val != 0:
      byte |= 0x80

    outp[0] = byte
    outp += 1
    if val == 0:
      return outp - start

def _pack_str (Packer xm, str value):
  cdef char *ptr
  cdef size_t size, offset, prev
  cdef unsigned int kind

  size = len (value)
  kind = STR_KIND (value)
  xm.resize ((size << (kind >> 1)) + 5 + sizeof (size_t))

  ptr = xm.ptr
  offset = prev = xm.offset

  ptr[offset] = tpcode.STR
  ptr[offset + 1] = kind
  offset += _write_uleb128 (xm.ptr, offset + 2, size) + 2

  if (kind & 1) == 0:
    # UCS-2 or UCS-4 string.
    offset += _get_padding (offset, kind)
    size <<= kind >> 1
  else:
    # ASCII or Latin-1.
    kind = 1

  memcpy (ptr + offset, PyUnicode_DATA (value), size + kind)
  xm.bump (offset - prev + size + kind)

cdef _pack_bytes (Packer xm, value):
  cdef char *ptr
  cdef const char *src
  cdef size_t offset, size, prev

  src = value
  size = len (value)

  xm.resize (10 + 1 + size)
  offset = prev = xm.offset
  ptr = xm.ptr

  ptr[offset] = tpcode.BYTES if type (value) is bytes else tpcode.BYTEARRAY
  offset += _write_uleb128 (xm.ptr, offset + 1, size) + 1

  memcpy (ptr + offset, src, size)
  xm.bump (offset - prev + size)

cdef dict _TYPECODES_MAP = {
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

cdef int _int_code (obj):
  if INT8_MIN <= obj <= INT8_MAX:
    return tpcode.INT8
  elif INT16_MIN <= obj <= INT16_MAX:
    return tpcode.INT16
  elif INT32_MIN <= obj <= INT32_MAX:
    return tpcode.INT32
  elif _IS_64_BIT and (INT64_MIN <= obj <= INT64_MAX):
    return tpcode.INT64
  return tpcode.NUM

cdef int _compute_basic_type (iterable):
  cdef int rv, tmp

  rv = -1
  for elem in iterable:
    if type (elem) is int:
      if rv > tpcode.INT64:
        # We had non-ints previously.
        return -1

      tmp = _int_code (elem)
      if tmp == tpcode.NUM:
        return -1

      rv = max (rv, tmp)
    elif type (elem) is float:
      if rv > 0 and rv != tpcode.FLOAT32 and rv != tpcode.FLOAT64:
        return -1

      rv = max (rv, _float_code (elem))
    else:
      return -1

  return rv

cdef _pack_flat_iter (Packer xm, value, Py_ssize_t at):
  cdef size_t tpoff, ix, pos
  cdef bint wide

  tpoff = xm.offset
  xm.putb (0)
  ulen = _write_uleb128 (xm.ptr, xm.offset, len (value))
  xm.bump (ulen + sizeof (size_t))

  offsets: list = []
  wide = False
  fmt: str = "I"

  for elem in value:
    offsets.append (xm.offset)
    if xm.offset >= INT32_MAX:
      wide = True
      fmt = "Q"

    xm.pack (elem if at < 0 else elem[at])
 
  xm.wbytes[tpoff] = b'Q' if wide else b'I'
  xm.align_to (sizeof (long long) if wide else sizeof (int))
  S_pack_into ("N", xm.wbytes, tpoff + 1 + ulen, xm.offset)
  xm.resize (len (offsets) * (sizeof (long long) if wide else sizeof (int)))
  xm.pack_struct (str (len (offsets)) + fmt, *offsets)

cdef _pack_array (Packer xm, value):
  cdef size_t off
  cdef int xtype
  cdef unsigned int ulen
  cdef size_t size

  xtype = _compute_basic_type (value)
  xm.putb (tpcode.LIST if type (value) is list else tpcode.TUPLE)
  size = len (value)
  xm.resize (11)   # 1 byte for typecode, 10 bytes for length.

  if xtype >= 0:
    # Inline integers or floats.
    xm.putb (xtype)
    xm.bump (_write_uleb128 (xm.ptr, xm.offset, size))
    xm.align_to (_BASIC_SIZES[xtype])
    xm.resize (size * _BASIC_SIZES[xtype])
    xm.pack_struct (str (size) + _BASIC_FMTS[xtype], *value)
    return

  _pack_flat_iter (xm, value, -1)

cdef _write_hashes (Packer xm, list hashes, bint wide):
  cdef char *ptr
  cdef Py_ssize_t ix

  ptr = xm.ptr
  ptr += xm.offset

  if wide:
    for ix in range (len (hashes)):
      (<unsigned long long *>ptr)[ix] = hashes[ix][0]
  else:
    for ix in range (len (hashes)):
      (<unsigned int *>ptr)[ix] = hashes[ix][0]

cdef _pack_set (Packer xm, value):
  cdef size_t size, hv
  cdef bint wide

  xm.putb (tpcode.SET)

  if _compute_basic_type (value) >= 0:
    xm.putb (1)   # Set contains inline objects.
    _pack_array (xm, tuple (sorted (value)))
    return

  hashes: list = []
  wide = False

  for index, elem in enumerate (value):
    hv = _xhash (elem, xm.hash_seed)
    if hv >= INT32_MAX:
      wide =  True

    hashes.append ((hv, elem))

  if wide:
    xm.putb (b'Q')
    size = sizeof (long long)
  else:
    xm.putb (b'I')
    size = sizeof (int)

  hashes = sorted (hashes, key = lambda elem: elem[0])
  xm.resize (10 + sizeof (size_t))   # uleb128 (10) + offset
  xm.bump (_write_uleb128 (xm.ptr, xm.offset, len (hashes)))

  xm.align_to (size)
  xm.resize (size + size * len (hashes))
  _write_hashes (xm, hashes, wide)

  xm.bump (size * len (hashes))
  xm.putb (tpcode.TUPLE)
  _pack_flat_iter (xm, hashes, 1)

cdef _pack_dict (Packer xm, value):
  cdef size_t hv, size, ix, prevoff
  cdef bint wide

  hashes: list = []
  fmt: str = "=I"

  xm.resize (24)
  xm.putb (tpcode.DICT)
  xm.bump (_write_uleb128 (xm.ptr, xm.offset, len (value)))

  wide = False
  for key, val in value.items ():
    hv = _xhash (key, xm.hash_seed)
    if hv >= INT32_MAX:
      wide = True
      fmt = "=Q"

    hashes.append ((hv, key, val))

  hashes = sorted (hashes, key = lambda elem: elem[0])

  if wide:
    xm.putb (b'Q')
    fmt = "=Q"
    size = sizeof (long long)
  else:
    xm.putb (b'I')
    size = sizeof (int)

  prevoff = xm.offset
  xm.bump (2 * sizeof (size_t))   # Ensure space for key and value tuples.
  xm.align_to (size)
  xm.resize (len (hashes) * size)

  _write_hashes (xm, hashes, wide)
  xm.bump (size * len (hashes))
  S_pack_into ("N", xm.wbytes, prevoff, xm.offset)

  xm.putb (tpcode.TUPLE)
  _pack_flat_iter (xm, hashes, 1)

  S_pack_into ("N", xm.wbytes, prevoff + sizeof (size_t), xm.offset)
  xm.putb (tpcode.LIST)
  _pack_flat_iter (xm, hashes, 2)

cdef inline object _encode_str (object x):
  return PyUnicode_AsEncodedString (x, "utf8", cy.NULL)

cdef _write_secret (Packer xm, str x):
  cdef size_t sz
  cdef object md, val

  val = _encode_str (x)
  sz = len (val)
  if xm.import_key is not None:
    # Include the checksum key in the stream.
    md = _encode_str (HMAC(xm.import_key, val, _HASH_METHOD).hexdigest ())
    xm.pack_struct ("I%ds" % len (md), len (md), md)

  xm.resize (sz + 10 + 1)
  xm.bump (_write_uleb128 (xm.ptr, xm.offset, sz))
  xm.bwrite (val)

cdef inline _write_type (Packer xm, typ):
  _write_secret (xm, typ.__module__ + "." + typ.__name__)

cdef dict _obj_vars (obj):
  ret = getattr (obj, "__dict__", _SENTINEL)
  if ret is not _SENTINEL:
    return ret if type (ret) is dict else dict (ret)

  ret = getattr (obj, "__slots__", _SENTINEL)
  if ret is _SENTINEL:
    raise TypeError ("cannot get attributes from object of type %r" %
                     type (obj))
  xmap = {}
  for key in ret:
    tmp = getattr (obj, key, _SENTINEL)
    if tmp is not _SENTINEL:
      xmap[key] = tmp

  return xmap

cdef _pack_generic (Packer xm, value):
  cdef size_t off, extra

  xm.putb (tpcode.OTHER)
  _write_type (xm, type (value))

  tmp = getattr (value, "__slot_types__", _SENTINEL)
  if tmp is not _SENTINEL:
    slot_types: dict = tmp
    obj_map: dict = {}
    for key, typ in slot_types.items ():
      val = getattr (value, key)
      if not isinstance (val, typ):
        val = typ (val)
      obj_map[key] = val
    xm.pack (obj_map)
  else:
    xm.pack (_obj_vars (value))

cdef inline size_t _upsize (size_t value):
  # Round up 'value' to the next power of 2.
  cdef size_t off

  off = 1
  while off <= 32:
    value |= value >> off
    off <<= 1

  return value + 1

def _pack_fixed (Packer xm, value):
  value.pack (xm)

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
  dict: _pack_dict,
  # Fixed-size integers and floats.
  i8:  _pack_fixed,
  i16: _pack_fixed,
  i32: _pack_fixed,
  i64: _pack_fixed,
  f32: _pack_fixed,
  f64: _pack_fixed,
}

cdef object _get_import_key (object key):
  if key is not None:
    if isinstance (key, str):
      key = _encode_str (key)
    elif not isinstance (key, bytes):
      raise TypeError ("import_key must be a string or bytes")

  return key

cdef class Packer:
  """
  Packs arbitrary objects into a byte stream.
  Instances of ``Packer`` are responsible for maintaining certain invariants,
  the most important being that objects are packed at aligned boundaries to
  make the unpacking operations fast and safe across architectures with
  strict constraints.
  """

  cdef size_t offset
  cdef bytearray wbytes
  cdef size_t wlen
  cdef dict id_cache
  cdef size_t hash_seed
  cdef dict custom_packers
  cdef object import_key
  cdef char* ptr

  def __init__ (self, offset = 0, id_cache = None, hash_seed = 0,
                custom_packers = None, initial_size = 8, import_key = None):
    """
    Constructs a Packer.

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
    self.ptr = self.wbytes

  cpdef resize (self, size_t extra):
    """
    Resize the underlying byte stream so that it has enough room for an
    additional ``extra`` bytes.
    """
    nsize = self.wlen + extra
    if nsize < <size_t> (len (self.wbytes)):
      return
    elif PyByteArray_Resize (self.wbytes, _upsize (nsize)) < 0:
      raise MemoryError

    self.ptr = self.wbytes

  cpdef bump (self, size_t off):
    "Bump the internal offset of the stream by ``off`` bytes."
    self.wlen += off
    self.offset += off

  cpdef putb (self, unsigned char bx):
    "Write a single byte to the stream."

    self.resize (1)
    self.ptr[self.wlen] = bx
    self.bump (1)

  cpdef zpad (self, size_t size):
    "Write ``size`` zeroes to the stream."
    self.resize (size)
    self.bump (size)

  cpdef align_to (self, size_t size):
    "Pad the stream so that the current position is aligned to ``size`` bytes."
    self.zpad (_get_padding (self.offset, size))

  @cy.final
  cdef _pack_struct (self, fmt, size_t offset, tuple args):
    cdef size_t size

    size = S_calcsize (fmt)
    self.resize (offset + size)
    S_pack_into (fmt, self.wbytes, offset, *args)
    return size

  def pack_struct (self, fmt, *args):
    "Same as calling ``struct.pack_into`` with the byte stream and offset."
    self.bump (self._pack_struct (fmt, self.wlen, args))

  def pack_struct_at (self, fmt, pos, *args):
    "Same as `pack_struct`, only this lets you specific the offset."
    self._pack_struct (fmt, pos, args)

  cpdef bwrite (self, obj):
    """
    Write a binary object to the stream.
    """
    cdef size_t size

    size = len (obj)
    self.resize (size)
    self.wbytes[self.wlen:self.wlen + size] = obj
    self.bump (size)

  cpdef as_bytearray (self):
    "Return a copy of the Packer's byte stream so far."
    return self.wbytes[:self.wlen]

  cpdef pack (self, obj):
    """
    Pack an arbitrary object in the byte stream.
    """
    cdef type ty
    cdef size_t prev

    prev = self.offset
    obj_id = id (obj)
    off = self.id_cache.get (obj_id)
    if off is not None:
      self.putb (tpcode.BACKREF)
      self.pack_struct ("N", off)
      return self.offset - prev

    ty = type (obj)
    if ty not in (int, float, str, bytes, bytearray):
      self.id_cache[obj_id] = prev

    try:
      fn = _BASIC_PACKERS.get (ty, None)
      if fn:
        fn (self, obj)
        return self.offset - prev

      code = _inline_pack (obj)
      if code >= 0:
        self.putb (code)
        return 1

      fn = _dispatch_type_impl (self.custom_packers, ty, direction.PACK)
      if fn is not None:
        self.putb (tpcode.CUSTOM)
        _write_type (self, ty)
        self.align_to (sizeof (long long))
        fn (self, obj)
      else:
        _pack_generic (self, obj)

      return self.offset - prev
    except Exception:
      self.id_cache.pop (obj_id, None)
      raise

  def write_secret (self, value):
    """
    Write an object encoded with the secret ``import_key``.
    """
    _write_secret (<Packer>self, value)

  def getoff (self):
    "Get the current offset in the packer."
    return self.offset

  @staticmethod
  def struct_size (fmt):
    return S_calcsize (fmt)

cdef inline object _cnum_unpack (Proxy self, size_t offs, cnum value):
  cdef size_t extra

  extra = _get_padding (offs, sizeof (value))
  self._assert_len (offs + extra + sizeof (value))
  return (<const cnum *> (self.base + offs + extra))[0]

cdef class Proxy:
  """
  Manages the underlying mapping so that objects can be safely and also
  efficiently 'proxied'.
  As a counterpart to the ``Packer`` class, a ``Proxy`` ensures that
  proxied objects have enough room in their backing store, and that their
  lifetimes never extend beyond their mapping's.
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
    Constructs a Proxy.

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

    :param int hash_seed *(default 0)*: See ``Packer.__init__``.

    :param bool verify_str *(default False)*: Whether to check for strings
      consistency (unicode-wise) when unpacking them.

    :param import_key *(default None)*: See ``Packer.__init__``.
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
  cdef int _assert_len (self, size_t size) except -1:
    if self.max_size < size:
      raise IndexError ("buffer too small")
    return 0

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

  @cy.final
  cdef int _byte_at (self, size_t ix) except -1:
    if ix >= self.max_size:
      raise IndexError ("buffer too small")

    return <unsigned char>self.base[ix]

  def __getitem__ (self, ix):
    "Return the byte at position ``ix``."
    return self.mbuf[ix]

  cdef _unpack_with_code (self, size_t offset, unsigned int code):
    cdef size_t size, rel_off
    cdef unsigned int ilen

    if code == tpcode.INT8:
      return _cnum_unpack[cy.schar] (self, offset, 0)
    elif code == tpcode.INT16:
      return _cnum_unpack[short] (self, offset, 0)
    elif code == tpcode.INT32:
      return _cnum_unpack[int] (self, offset, 0)
    elif code == tpcode.INT64:
      return _cnum_unpack[cy.longlong] (self, offset, 0)
    elif code == tpcode.FLOAT32:
      return _cnum_unpack[float] (self, offset, 0)
    elif code == tpcode.FLOAT64:
      return _cnum_unpack[double] (self, offset, 0)
    elif code == tpcode.NUM:
      self._assert_len (offset + sizeof (ilen))
      memcpy (&ilen, self.base + offset, sizeof (ilen))
      offset += sizeof (ilen)
      return Int_From_Bytes (self.mbuf[offset:offset + ilen],
                             SYS_endian, signed = True)
    elif code == tpcode.STR:
      return ProxyStr._make (self, offset)
    elif code in (tpcode.BYTES, tpcode.BYTEARRAY):
      offset = _read_uleb128 (self, offset, &size)
      mbx = self.mbuf[offset:offset + size]
      return bytes(mbx) if code == tpcode.BYTES else bytearray(mbx)
    elif code == tpcode.NONE:
      return None
    elif code == tpcode.TRUE:
      return True
    elif code == tpcode.FALSE:
      return False
    elif code == tpcode.LIST or code == tpcode.TUPLE:
      return ProxyList._make (self, offset, code == tpcode.LIST)
    elif code == tpcode.SET:
      return ProxySet._make (self, offset)
    elif code == tpcode.DICT:
      return ProxyDict._make (self, offset)
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
      return fn (typ, self,
                 offset + _get_padding (offset, sizeof (long long)))
    raise TypeError ("Cannot unpack typecode %r" % code)

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

  def read_secret (self, off = None):
    cdef size_t offset
    cdef size_t *offp

    if off is not None:
      offset = off
      offp = &offset
    else:
      offp = &self.offset

    return _read_secret (<Proxy>self, offp)

############################################

cdef inline object _builtin_read (void *buf, unsigned int code):
  if code == tpcode.INT8:
    return (<signed char *>buf)[0]
  elif code == tpcode.INT16:
    return (<short *>buf)[0]
  elif code == tpcode.INT32:
    return (<int *>buf)[0]
  elif code == tpcode.INT64:
    return (<long long *>buf)[0]
  elif code == tpcode.FLOAT32:
    return (<float *>buf)[0]
  return (<double *>buf)[0]

cdef inline void _builtin_write (void *buf, object obj, unsigned int code):
  if code == tpcode.INT8:
    (<signed char *>buf)[0] = obj
  elif code == tpcode.INT16:
    (<short *>buf)[0] = obj
  elif code == tpcode.INT32:
    (<int *>buf)[0] = obj
  elif code == tpcode.INT64:
    (<long long *>buf)[0] = obj
  elif code == tpcode.FLOAT32:
    (<float *>buf)[0] = obj
  elif code == tpcode.FLOAT64:
    (<double *>buf)[0] = obj

  atomic_fence_rel ()

cdef inline bint _builtin_acas_impl (cnum *ptr, object o_exp, object o_nval):
  cdef cnum exp, val

  exp = o_exp
  val = o_nval
  return atomic_cas_bool (ptr, &exp, &val)

cdef inline object _cfloat_aadd (cfloat *ptr, object val):
  cdef long long qexp, qnew
  cdef int iexp, inew
  cdef cfloat delta, tmp, new

  delta = val
  while 1:
    tmp = ptr[0]
    new = tmp + delta
    if cfloat is float:
      memcpy (&iexp, &tmp, sizeof (iexp))
      memcpy (&inew, &new, sizeof (inew))
      if atomic_cas_bool (<int *>ptr, &iexp, &inew):
        return tmp
    elif not _IS_64_BIT:
      raise TypeError ("cannot perform atomic operations on doubles")
    else:
      memcpy (&qexp, &tmp, sizeof (qexp))
      memcpy (&qnew, &new, sizeof (qnew))
      if atomic_cas_bool (<long long *>ptr, &qexp, &qnew):
        return tmp

cdef inline object _builtin_aadd_impl (cnum *ptr, object val):
  cdef cnum xv

  xv = val
  atomic_add (ptr, &xv)
  return xv

cdef inline object _builtin_aadd (void *buf, object val, unsigned int code):
  if code == tpcode.INT8:
    return _builtin_aadd_impl[cy.schar] (<signed char *>buf, val)
  elif code == tpcode.INT16:
    return _builtin_aadd_impl[short] (<short *>buf, val)
  elif code == tpcode.INT32:
    return _builtin_aadd_impl[int] (<int *>buf, val)
  elif code == tpcode.INT64:
    return _builtin_aadd_impl[cy.longlong] (<long long *>buf, val)
  elif code == tpcode.FLOAT32:
    return _cfloat_aadd[float] (<float *>buf, val)
  else:
    return _cfloat_aadd[double] (<double *>buf, val)

cdef object _builtin_acas (void *buf, object exp,
                           object nval, unsigned int code):
  if code == tpcode.INT8:
    return _builtin_acas_impl[cy.schar] (<signed char *>buf, exp, nval)
  elif code == tpcode.INT16:
    return _builtin_acas_impl[short] (<short *>buf, exp, nval)
  elif code == tpcode.INT32:
    return _builtin_acas_impl[int] (<int *>buf, exp, nval)
  elif code == tpcode.INT64:
    return _builtin_acas_impl[cy.longlong] (<long long *>buf, exp, nval)
  elif code == tpcode.FLOAT32:
    return _builtin_acas_impl[float] (<float *>buf, exp, nval)
  else:
    return _builtin_acas_impl[double] (<double *>buf, exp, nval)

cdef size_t _read_uleb128 (Proxy proxy, size_t off, size_t *valp) except? 0:
  cdef size_t ret, shift
  cdef unsigned char byte

  shift = ret = 0
  while True:
    byte = proxy._byte_at (off)
    ret |= (byte & 0x7f) << shift
    off += 1

    if not (byte & 0x80):
      valp[0] = ret
      return off

    shift += 7

cdef class ProxyList:
  cdef Proxy proxy
  cdef size_t offset
  cdef size_t size
  cdef unsigned int code
  cdef Py_ssize_t step
  cdef bint mutable

  @staticmethod
  cdef ProxyList _make (Proxy proxy, size_t off, bint mutable):
    cdef ProxyList self
    cdef size_t esz
    cdef unsigned int ty
    cdef bint rdwr

    self = ProxyList.__new__ (ProxyList)
    self.proxy = proxy
    self.offset = off

    self.code = ty = self.proxy[self.offset]
    self.offset = _read_uleb128 (self.proxy, self.offset + 1, &self.size)

    if _is_inline_code (ty):
      # Inline objects: Integers or floats.
      esz = _BASIC_SIZES[ty]
      self.offset += _get_padding (self.offset, esz)
      self.proxy._assert_len (self.offset + self.size * esz)
    else:
      # Indirect references to objects.
      self.proxy._assert_len (self.offset + sizeof (self.offset))
      memcpy (&self.offset, self.proxy.base + self.offset,
              sizeof (self.offset))
      proxy._assert_len (self.offset + self.size *
                         (sizeof (int) if self.code == b'I'
                                       else sizeof (long long)))

    self.step = 1
    self.mutable = mutable and self.proxy.rdwr
    return self

  def __len__ (self):
    return self.size

  @cy.final
  cdef void* _c_ptr (self, size_t idx, unsigned int *codep):
    cdef void *base
    cdef size_t offset, extra
    cdef unsigned int code

    base = self.proxy.base + self.offset

    if not _is_inline_code (self.code):
      if self.code == b'I':
        offset = (<unsigned int *>base)[idx]
      else:
        offset = (<unsigned long long *>base)[idx]

      code = <unsigned char>self.proxy.base[offset]
      codep[0] = code

      if not _is_inline_code (code):
        return self.proxy.base + offset

      extra = _get_padding (offset + 1, _BASIC_SIZES[code])
      self.proxy._assert_len (offset + extra + 1 + _BASIC_SIZES[code])
      return self.proxy.base + offset + extra + 1

    codep[0] = self.code
    if self.code == tpcode.INT8:
      return (<signed char *>base) + idx
    elif self.code == tpcode.INT16:
      return (<short *>base) + idx
    elif self.code == tpcode.INT32:
      return (<int *>base) + idx
    elif self.code == tpcode.INT64:
      return (<long long *>base) + idx
    elif self.code == tpcode.FLOAT32:
      return (<float *>base) + idx
    else:
      return (<double *>base) + idx

  @cy.final
  cdef inline object _c_index (self, Py_ssize_t pos):
    cdef void *p
    cdef unsigned int code

    if pos < 0:
      pos += self.size

    if pos >= <Py_ssize_t>self.size or pos < 0:
      raise IndexError ("index out of bounds")

    p = self._c_ptr (pos * self.step, &code)
    if _is_inline_code (code):
      if self.mutable:
        atomic_fence_acq ()

      return _builtin_read (p, code)

    return self.proxy._unpack_with_code (<char *>p - self.proxy.base + 1, code)

  @cy.cdivision (True)
  def __getitem__ (self, idx):
    cdef Py_ssize_t pos, n, start, end, step, rsize
    cdef ProxyList rv

    if isinstance (idx, int):
      pos = idx
      n = self.size

      if pos < 0:
        pos += n
        if pos < 0:
          raise IndexError ("index out of bounds")
      elif pos >= n:
        raise IndexError ("index out of bounds")

      return self._c_index (pos)
    elif not isinstance (idx, slice):
      raise TypeError ("index must be an integer or slice")

    PySlice_GetIndices (idx, self.size, &start, &end, &step)

    rv = ProxyList.__new__ (ProxyList)
    rv.proxy = self.proxy
    rv.code = self.code

    rsize = (end - start) // step
    if ((end - start) % step) != 0:
      rsize += 1

    rv.size = rsize
    rv.offset = self.offset

    if _is_inline_code (rv.code):
      start *= _BASIC_SIZES[rv.code]
    elif rv.code == b"I":
      start *= sizeof (int)
    else:
      start *= sizeof (long long)

    rv.offset += start * self.step
    rv.step = step * self.step
    rv.mutable = self.mutable
    return rv

  cdef Py_ssize_t _mut_idx (self, Py_ssize_t idx, unsigned int *cdp) except? -1:
    cdef void *ret

    if not self.mutable:
      raise TypeError ("cannot modify read-only proxy list")

    if idx < 0:
      idx += self.size

    idx *= self.step
    if idx < 0 or idx >= <Py_ssize_t>self.size:
      raise IndexError ("index out of bounds")

    ret = self._c_ptr (idx, cdp)
    if not _is_inline_code (cdp[0]):
      raise TypeError ("cannot modify non-primitive proxy list element")

    return (<char *>ret) - self.proxy.base

  def __setitem__ (self, idx, value):
    cdef Py_ssize_t mi
    cdef unsigned int code

    mi = self._mut_idx (idx, &code)
    _builtin_write (self.proxy.base + mi, value, code)

  def atomic_cas (self, idx, exp, nval):
    """
    Atomically compare the value at ``idx``, and if it's equal to ``exp``, set
    it to ``nval``. Returns True if the operation was successful.
    """
    cdef Py_ssize_t pos
    cdef unsigned int code

    pos = self._mut_idx (idx, &code)
    return _builtin_acas (self.proxy.base + pos, exp, nval, code)

  def atomic_add (self, idx, val):
    """
    Atomically add ``val`` to the value at ``idx``, returning the previous
    value at that position.
    """
    cdef Py_ssize_t pos
    cdef unsigned int code

    pos = self._mut_idx (idx, &code)
    return _builtin_aadd (self.proxy.base + pos, val, code)

  def __hash__ (self):
    return _xhash (self, self.proxy.hash_seed)

  def __iter__ (self):
    cdef size_t i

    for i in range (self.size):
      yield self._c_index (i)

  @cy.final
  cdef str _to_str (ProxyList self, dict id_map):
    cdef ProxyList other

    if len (self) == 0:
      return '[]'

    id_map[self.offset] = self
    sio = StringIO()
    swrite = sio.write

    swrite ('[')
    for elem in self:
      if type(elem) is not ProxyList:
        swrite (str (elem))
      else:
        other = (<ProxyList>elem)
        if other.offset in id_map:
          swrite('[...]')
        else:
          id_map[other.offset] = other
          swrite (other._to_str (id_map))

      swrite (', ')
    return sio.getvalue()[:-2] + ']'

  def __str__(self):
    if _is_inline_code (self.code):
      return "[%s]" % ",".join ([str (x) for x in self])

    return self._to_str({id(self): self})

  def __repr__ (self):
    return "ProxyList(%s)" % self

  def __add__ (self, x):
    cdef bint rdwr
    cdef type typ

    if not isinstance (x, ProxyList):
      typ = list if (<ProxyList>self).mutable else tuple
      if typ is not type (x):
        raise TypeError ("cannot add ProxyList to %r" % type(x).__name__)
    else:
      rdwr = (<ProxyList>x).mutable
      typ = list if rdwr else tuple
      if ((isinstance (self, ProxyList) and
          rdwr != (<ProxyList>self).mutable) or
            (not isinstance (self, ProxyList) and
              not isinstance (self, typ))):
        raise TypeError ("cannot add proxy lists of different mutability")

    return typ (IT_chain (self, x))

  def copy (self):
    return list (self) if self.mutable else self

  def index (self, value, start = 0, stop = WORD_MAX):
    cdef size_t istart, istop, n

    istart, istop = start, stop
    n = self.size
    istop = min (istop, n)

    while istart < istop:
      if self._c_index (istart) == value:
        return istart
      istart += 1

    raise ValueError ("%r is not in list" % value)

  def __contains__ (self, value):
    cdef size_t i

    for i in range (self.size):
      if self._c_index (i) == value:
        return True
    return False

  def count (self, value):
    cdef size_t i, n

    n = 0
    for i in range (self.size):
      if self._c_index (i) == value:
        n += 1
    return n

  @cy.final
  cdef int _cmp (self, x, bint err, bint eq) except -2:
    cdef size_t alen, blen, i

    if not isinstance (x, (tuple, list, ProxyList)):
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
      a = self._c_index (i)
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
    if isinstance (self, ProxyList):
      return (<ProxyList>self)._cmp (x, False, True) == 0
    return (<ProxyList>x)._cmp (self, False, True) == 0

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
    typ = list if self.mutable else tuple
    return typ (unproxy (x) for x in self)

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

cdef class ProxyStr:
  cdef Proxy proxy
  cdef str uobj

  @staticmethod
  cdef ProxyStr _make (Proxy proxy, size_t off):
    cdef ProxyStr self
    cdef size_t size
    cdef unsigned int kind, orig_kind

    self = ProxyStr.__new__ (ProxyStr)
    self.proxy = proxy

    orig_kind = kind = self.proxy[off]
    off = _read_uleb128 (proxy, off + 1, &size)

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
    cdef ProxyStr rv

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

    rv = ProxyStr.__new__ (ProxyStr)
    rv.proxy = self.proxy
    rv.uobj = STR_NEW (STR_KIND (self.uobj), min (end - start, slen),
                       (<char *>PyUnicode_DATA (self.uobj)) + start)
    return rv

  # These arithmetic operators are placeholders until we can install
  # the real implementations once the 'ProxyStr' type is finalized.
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
    cdef ProxyStr this

    if isinstance (self, ProxyStr):
      this = <ProxyStr>self
      if isinstance (x, ProxyStr):
        return fn (this.uobj, (<ProxyStr>x).uobj)
      elif isinstance (x, str):
        return fn (this.uobj, x)
      else:
        return fn (str (this), x)
    else:
      this = <ProxyStr>x
      if isinstance (self, ProxyStr):
        return fn ((<ProxyStr>self).uobj, this.uobj)
      elif isinstance (self, str):
        return fn (self, this.uobj)
      else:
        return fn (self, str (this))

  def __eq__ (self, x):
    return ProxyStr._cmp_impl (self, x, OP_eq)

  def __ge__ (self, x):
    return ProxyStr._cmp_impl (self, x, OP_ge)

  def __gt__ (self, x):
    return ProxyStr._cmp_impl (self, x, OP_gt)

  def __iter__ (self):
    for ch in self.uobj:
      yield ch

  def __le__ (self, x):
    return ProxyStr._cmp_impl (self, x, OP_le)

  def __lt__ (self, x):
    return ProxyStr._cmp_impl (self, x, OP_lt)

  def __ne__ (self, x):
    return ProxyStr._cmp_impl (self, x, OP_ne)

# The following is a kludge to support arbitrary argument order in
# arithmetic operators. We need to patch things this way because not
# all Cython versions can be convinced.

cdef str _ProxyStr_op_impl (self_, x, typ, bint self_type, fn):
  cdef ProxyStr this

  # For standard operators (i.e: 'str.__add__'), we can use the raw unicode
  # object, since we know there's no danger there. Otherwise, for custom
  # types, we have to copy into a fresh object.
  this = None
  if isinstance (self_, ProxyStr):
    if isinstance (x, typ):
      this = self_
      ret = fn (this.uobj, x)
    elif self_type and isinstance (x, ProxyStr):
      this = self_
      ret = fn (this.uobj, (<ProxyStr>x).uobj)
    else:
      ret = fn (str (self_), x)
  elif isinstance (self_, typ):
    this = x
    ret = fn (self_, this.uobj)
  else:
    ret = fn (self_, str (x))

  return ret if this is None or ret is not this.uobj else this

cdef _ProxyStr_add (x, y):
  return _ProxyStr_op_impl (x, y, str, True, OP_add)

cdef _ProxyStr_mod (x, y):
  return _ProxyStr_op_impl (x, y, str, False, OP_mod)

cdef _ProxyStr_mul (x, y):
  return _ProxyStr_op_impl (x, y, int, False, OP_mul)

# Install the new operators.
TYPE_PATCH (<PyTypeObject *>ProxyStr, _ProxyStr_add,
            _ProxyStr_mod, _ProxyStr_mul)

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
for code, *ty in ((0x1073952, frozenset, ProxySet),
                  (0x81603094, tuple, ProxyList)):
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
  elif isinstance (obj, ProxyStr):
    ret = _hash_str ((<ProxyStr>obj).uobj)
  elif isinstance (obj, ProxyDict):
    ret = hash (obj)
  else:
    ty = type (obj)
    if isinstance (obj, ProxyList) and (<ProxyList>obj).mutable:
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

cdef inline Py_ssize_t _cfloat_diff (cfloat x, cfloat y):
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
    # X - nan
    return -1
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
    if cnum is double or cnum is float:
      cmpr = _cfloat_diff (tmp, value)
    else:
      cmpr = <Py_ssize_t> (tmp - value)

    if cmpr == 0:
      return 1
    elif cmpr > 0:
      n = step - 1
      step = min (step >> 2, <size_t>64)
      while step > 0:
        tmp = (<const cnum *>ptr)[n]
        if cnum is double or cnum is float:
          cmpr = _cfloat_diff (tmp, value)
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
        if cnum is double or cnum is float:
          cmpr = _cfloat_diff (tmp, value)
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
    tmp = hidxs[step]

    if tmp == hval:
      while step > 0:
        if hidxs[step - 1] != tmp:
          break
        step -= 1
      return step + 1
    elif tmp > hval:
      # New range is from [0 .. step - 1]
      n = step - 1
      step = min (step >> 2, <size_t>512 // sizeof (hidxs[0]))
      while step > 0:
        tmp = hidxs[n]
        if tmp > hval:
          step -= 1
          n -= 1
        elif tmp == hval:
          while n > 0:
            if hidxs[n - 1] != tmp:
              break
            n -= 1
          return n + 1
        else:
          return 0
      n += 1
    else:
      # New range is [step + 1 .. N]
      i = step + 1
      step = min (step >> 2, <size_t>512 // sizeof (hidxs[0]))
      while step > 0:
        tmp = hidxs[i]
        if tmp < hval:
          step -= 1
          i += 1
        elif tmp == hval:
          while i > 0:
            if hidxs[i - 1] != tmp:
              break
            i -= 1
          return i + 1
        else:
          return 0
  return 0

cdef size_t _find_obj_by_hidx (hidx_type hidxs, size_t ix,
                               obj, ProxyList keys):
  cdef size_t hval

  if ix == 0:
    return ix

  ix -= 1
  hval = hidxs[ix]

  while 1:
    key = keys._c_index (ix)
    ix += 1

    if obj == key:
      return ix
    elif ix == keys.size or hidxs[ix] != hval:
      return 0

################################
# Functions on sets.

cdef inline bint _cnum_lt (cnum x, cnum y):
  if cnum is double or cnum is float:
    return _cfloat_diff (x, y) < 0
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
    for i in range (l1):
      if cnum is double or cnum is float:
        if _cfloat_diff ((<cnum *>p1)[i], (<cnum *>p2)[i]) != 0:
          return 0
      else:
        if (<cnum *>p1)[i] != (<cnum *>p2)[i]:
          return 0
    return 1

  i = j = 0
  while j < l2:
    if i == l1 or _cnum_lt ((<const cnum *>p2)[j], (<const cnum *>p1)[i]):
      return 0
    elif not _cnum_lt ((<const cnum *>p1)[i], (<const cnum *>p2)[j]):
      j += 1
    i += 1

  return 1

cdef class ProxySet:
  cdef ProxyList indices
  cdef unsigned int hcode
  cdef void* hashes

  @staticmethod
  cdef ProxySet _make (Proxy proxy, size_t offset):
    cdef ProxySet self
    cdef size_t size, esz
    cdef unsigned char code

    self = ProxySet.__new__ (ProxySet)
    code = proxy[offset]
    if code == 1:
      self.indices = proxy._unpack (offset + 1)
      self.hashes = cy.NULL
      self.hcode = self.indices.code
    else:
      self.hcode = code
      esz = sizeof (int) if code == b'I' else sizeof (long long)
      offset = _read_uleb128 (proxy, offset + 1, &size)
      offset += _get_padding (offset, esz)
      self.hashes = <char *>proxy.base + offset
      self.indices = proxy._unpack (offset + esz * size)
      if size != self.indices.size:
        raise ValueError ('set and indices length mismatch')

    return self

  def __len__ (self):
    return self.indices.size

  @cy.final
  cdef set _union (self, ProxySet pset):
    cdef ProxyList ix1, ix2
    cdef const unsigned char *p1
    cdef const unsigned char *p2
    cdef set out

    ix1, ix2 = self.indices, pset.indices
    if self.hcode == pset.hcode and _is_inline_code (self.hcode):
      out = set ()
      p1 = <const unsigned char *> (ix1.proxy.base + ix1.offset)
      p2 = <const unsigned char *> (ix2.proxy.base + ix2.offset)

      if ix1.code == tpcode.INT8:
        _cnum_set_union[cy.schar] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT16:
        _cnum_set_union[short] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT32:
        _cnum_set_union[int] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT64:
        _cnum_set_union[cy.longlong] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.FLOAT32:
        _cnum_set_union[float] (p1, ix1.size, p2, ix2.size, out, 0)
      else:
        _cnum_set_union[double] (p1, ix1.size, p2, ix2.size, out, 0)

      return out
    else:
      return set(self).union (pset)

  @cy.final
  cdef set _intersection (self, ProxySet pset):
    cdef ProxyList ix1, ix2
    cdef const unsigned char *p1
    cdef const unsigned char *p2
    cdef set out

    ix1, ix2 = self.indices, pset.indices
    if self.hcode == pset.hcode and _is_inline_code (self.hcode):
      out = set ()
      p1 = <const unsigned char *> (ix1.proxy.base + ix1.offset)
      p2 = <const unsigned char *> (ix2.proxy.base + ix2.offset)

      if ix1.code == tpcode.INT8:
        _cnum_set_intersection[cy.schar] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT16:
        _cnum_set_intersection[short] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT32:
        _cnum_set_intersection[int] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT64:
        _cnum_set_intersection[cy.longlong] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.FLOAT32:
        _cnum_set_intersection[float] (p1, ix1.size, p2, ix2.size, out, 0)
      else:
        _cnum_set_intersection[double] (p1, ix1.size, p2, ix2.size, out, 0)

      return out
    else:
      return set(self).intersection (pset)

  @cy.final
  cdef set _difference (self, ProxySet pset):
    cdef ProxyList ix1, ix2
    cdef const unsigned char *p1
    cdef const unsigned char *p2
    cdef set out

    ix1, ix2 = self.indices, pset.indices
    if self.hcode == pset.hcode and _is_inline_code (self.hcode):
      out = set ()
      p1 = <const unsigned char *> (ix1.proxy.base + ix1.offset)
      p2 = <const unsigned char *> (ix2.proxy.base + ix2.offset)

      if ix1.code == tpcode.INT8:
        _cnum_set_difference[cy.schar] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT16:
        _cnum_set_difference[short] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT32:
        _cnum_set_difference[int] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT64:
        _cnum_set_difference[cy.longlong] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.FLOAT32:
        _cnum_set_difference[float] (p1, ix1.size, p2, ix2.size, out, 0)
      else:
        _cnum_set_difference[double] (p1, ix1.size, p2, ix2.size, out, 0)

      return out
    else:
      return set(self).difference (pset)

  @cy.final
  cdef set _symdiff (self, ProxySet pset):
    cdef ProxyList ix1, ix2
    cdef const unsigned char *p1
    cdef const unsigned char *p2
    cdef set out

    ix1, ix2 = self.indices, pset.indices
    if self.hcode == pset.hcode and _is_inline_code (self.hcode):
      out = set ()
      p1 = <const unsigned char *> (ix1.proxy.base + ix1.offset)
      p2 = <const unsigned char *> (ix2.proxy.base + ix2.offset)

      if ix1.code == tpcode.INT8:
        _cnum_set_symdiff[cy.schar] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT16:
        _cnum_set_symdiff[short] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT32:
        _cnum_set_symdiff[int] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.INT64:
        _cnum_set_symdiff[cy.longlong] (p1, ix1.size, p2, ix2.size, out, 0)
      elif ix1.code == tpcode.FLOAT32:
        _cnum_set_symdiff[float] (p1, ix1.size, p2, ix2.size, out, 0)
      else:
        _cnum_set_symdiff[double] (p1, ix1.size, p2, ix2.size, out, 0)

      return out
    else:
      return set(self).symmetric_difference (pset)

  def __contains__ (self, value):
    cdef ProxyList indices
    cdef Proxy proxy
    cdef size_t n, ix
    cdef const unsigned int *iarray
    cdef const unsigned long long *qarray
    cdef const unsigned char *ptr

    indices = self.indices
    proxy = indices.proxy
    n = indices.size
    ptr = <const unsigned char *> (proxy.base + indices.offset)

    if self.hcode == tpcode.INT8:
      return _cnum_find_sorted[cy.schar] (ptr, n, value, 0, 0)
    elif self.hcode == tpcode.INT16:
      return _cnum_find_sorted[short] (ptr, n, value, 0, 0)
    elif self.hcode == tpcode.INT32:
      return _cnum_find_sorted[int] (ptr, n, value, 0, 0)
    elif self.hcode == tpcode.INT64:
      return _cnum_find_sorted[cy.longlong] (ptr, n, value, 0, 0)
    elif self.hcode == tpcode.FLOAT32:
      return _cnum_find_sorted[float] (ptr, n, value, 0, 0)
    elif self.hcode == tpcode.FLOAT64:
      return _cnum_find_sorted[double] (ptr, n, value, 0, 0)
    elif self.hcode == b"I":
      iarray = <const unsigned int *>self.hashes
      ix = _find_hidx (iarray, _xhash (value, proxy.hash_seed), n)
      return _find_obj_by_hidx (iarray, ix, value, indices) != 0
    else:
      qarray = <const unsigned long long *>self.hashes
      ix = _find_hidx (qarray, _xhash (value, proxy.hash_seed), n)
      return _find_obj_by_hidx (qarray, ix, value, indices) != 0

  def __iter__ (self):
    return iter (self.indices)

  def union (self, *args):
    if not args:
      return self
    elif len (args) == 1:
      tmp = args[0]
      if isinstance (tmp, ProxySet):
        return self._union (<ProxySet>tmp)
    return set(self).union (*args)

  def intersection (self, *args):
    if not args:
      return self
    elif len (args) == 1:
      tmp = args[0]
      if isinstance (tmp, ProxySet):
        return self._intersection (<ProxySet>tmp)
    return set(self).intersection (*args)

  def difference (self, *args):
    if not args:
      return self
    elif len (args) == 1:
      tmp = args[0]
      if isinstance (tmp, ProxySet):
        return self._difference (<ProxySet>tmp)
    return set(self).difference (*args)

  def symmetric_difference (self, *args):
    if not args:
      return self
    elif len (args) == 1:
      tmp = args[0]
      if isinstance (tmp, ProxySet):
        return self._symdiff (<ProxySet>tmp)
    return set(self).symmetric_difference (*args)

  def __and__ (self, x):
    cdef ProxySet this

    if isinstance (self, ProxySet):
      this = <ProxySet>self
      if isinstance (x, ProxySet):
        return this._intersection (<ProxySet>x)
      return set(this).intersection (x)
    elif not isinstance (self, (set, frozenset)):
      raise TypeError ("cannot compute intersection between %r and %r" %
                       (type(self).__name__, type(x).__name__))
    return self.intersection (set (x))

  def __or__ (self, x):
    cdef ProxySet this

    if isinstance (self, ProxySet):
      this = <ProxySet>self
      if isinstance (x, ProxySet):
        return this._union (<ProxySet>x)
      return set(this).union (x)
    elif not isinstance (self, (set, frozenset)):
      raise TypeError ("cannot compute union between %r and %r" %
                       (type(self).__name__, type(x).__name__))
    return self.union (set (x))

  def __sub__ (self, x):
    cdef ProxySet this

    if isinstance (self, ProxySet):
      this = <ProxySet>self
      if isinstance (x, ProxySet):
        return this._difference (<ProxySet>x)
      return set(this).difference (x)
    elif not isinstance (self, (set, frozenset)):
      raise TypeError ("cannot compute difference between %r and %r" %
                       (type(self).__name__, type(x).__name__))
    return self.difference (set (x))

  def __xor__ (self, x):
    cdef ProxySet this

    if isinstance (self, ProxySet):
      this = <ProxySet>self
      if isinstance (x, ProxySet):
        return this._symdiff (<ProxySet>x)
      return set(this).symmetric_difference (x)
    elif not isinstance (self, (set, frozenset)):
      raise TypeError ("cannot compute symmetric difference between %r and %r" %
                       (type(self).__name__, type(x).__name__))
    return self.symmetric_difference (set (x))

  cdef bint _eq (self, x):
    cdef ProxySet ps
    cdef ProxyList ix1, ix2

    if (_is_inline_code (self.hcode) and isinstance (x, ProxySet) and
        (<ProxySet>x).hcode == self.hcode):
      ps = <ProxySet>x
      ix1, ix2 = self.indices, ps.indices
      return (ps.indices.size == self.indices.size and
              memcmp (ix1.proxy.base + ix1.offset, ix2.proxy.base + ix2.offset,
                      ix1.size * sizeof (size_t)) == 0)

    if not isinstance (x, (set, frozenset, ProxySet)) or len (x) != len (self):
      return False
    for elem in self:
      if elem not in x:
        return False
    return True

  def __eq__ (self, x):
    if isinstance (self, ProxySet):
      return (<ProxySet>self)._eq (x)
    return (<ProxySet>x)._eq (self)

  cdef bint _subset (self, x, bint lt):
    cdef bint ret
    cdef ProxyList ix1, ix2
    cdef const void *p1
    cdef const void *p2

    if (_is_inline_code (self.hcode) and
        isinstance (x, ProxySet) and
        (<ProxySet>x).hcode == self.hcode):
      ix1, ix2 = self.indices, (<ProxySet>x).indices
      p1 = <const void *> (ix1.proxy.base + ix1.offset)
      p2 = <const void *> (ix2.proxy.base + ix2.offset)

      if ix1.size > ix2.size:
        ret = False
      elif self.hcode == tpcode.INT8:
        ret = _cnum_set_includes[cy.schar] (p2, ix2.size, p1, ix1.size, 0)
      elif self.hcode == tpcode.INT16:
        ret = _cnum_set_includes[short] (p2, ix2.size, p1, ix1.size, 0)
      elif self.hcode == tpcode.INT32:
        ret = _cnum_set_includes[int] (p2, ix2.size, p1, ix1.size, 0)
      elif self.hcode == tpcode.INT64:
        ret = _cnum_set_includes[cy.longlong] (p2, ix2.size, p1, ix1.size, 0)
      elif self.hcode == tpcode.FLOAT32:
        ret = _cnum_set_includes[float] (p2, ix2.size, p1, ix1.size, 0)
      else:
        ret = _cnum_set_includes[double] (p2, ix2.size, p1, ix1.size, 0)

      if lt:
        ret = ret and ix1.size < ix2.size

    elif (not isinstance (x, (set, frozenset, ProxySet)) or
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
    if isinstance (self, ProxySet):
      return (<ProxySet>self)._subset (x, True)
    return (<ProxySet>x)._subset (self, True)

  def __le__ (self, x):
    if isinstance (self, ProxySet):
      return (<ProxySet>self)._subset (x, False)
    return (<ProxySet>x)._subset (self, False)

  def __gt__ (self, x):
    return x < self

  def __ge__ (self, x):
    return x <= self

  def __str__ (self):
    return "{%s}" % ",".join ([str (x) for x in self])

  def __repr__ (self):
    return "ProxySet(%s)" % self

  @cy.final
  cdef _toset (self):
    rv = set ()
    for elem in self:
      rv.add (unproxy (elem))
    return rv

########################################

cdef class ProxyDict:
  cdef void* hashes
  cdef ProxyList tkeys
  cdef ProxyList tvalues
  cdef bint wide

  @staticmethod
  cdef ProxyDict _make (Proxy proxy, size_t offset):
    cdef ProxyDict self
    cdef size_t size
    cdef size_t kv_off[2]
    cdef unsigned char code

    self = ProxyDict.__new__ (ProxyDict)
    offset = _read_uleb128 (proxy, offset, &size)
    self.wide = proxy[offset] == 81   # equal to 'Q'
    proxy._assert_len (offset + 1 + 2 * sizeof (size_t))
    memcpy (&kv_off[0], proxy.base + offset + 1, sizeof (kv_off))
    offset += sizeof (kv_off)
    offset += _get_padding (offset + 1, sizeof (long long)
                                        if self.wide else sizeof (int)) + 1
    self.tkeys = proxy._unpack (kv_off[0])
    self.tvalues = proxy._unpack (kv_off[1])
    self.hashes = proxy.base + offset
    proxy._assert_len (offset + self.tkeys.size *
                       (sizeof (long long) if self.wide else sizeof (int)))

    return self

  def __len__ (self):
    return self.tkeys.size

  @cy.final
  cdef object _c_get (self, key, dfl):
    cdef size_t ix, hv
    cdef const unsigned int *iarray
    cdef const unsigned long long *qarray

    hv = _xhash (key, self.tkeys.proxy.hash_seed)

    if not self.wide:
      iarray = <const unsigned int *>self.hashes
      ix = _find_hidx (iarray, hv, self.tkeys.size)
      ix = _find_obj_by_hidx (iarray, ix, key, self.tkeys)
      if ix != 0:
        return self.tvalues._c_index (ix - 1)
    else:
      qarray = <const unsigned long long *>self.hashes
      ix = _find_hidx (qarray, hv, self.tkeys.size)
      ix = _find_obj_by_hidx (qarray, ix, key, self.tkeys)
      if ix != 0:
        return self.tvalues._c_index (ix - 1)

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

  def keys (self):
    return iter (self.tkeys)

  def values (self):
    return iter (self.tvalues)

  def items (self):
    cdef size_t ix

    for ix in range (self.tkeys.size):
      yield (self.tkeys._c_index (ix), self.tvalues._c_index (ix))

  @cy.final
  cdef _todict (self):
    ret: dict = {}

    for key, val in self.items ():
      ret[unproxy (key)] = unproxy (val)

    return ret

  def __iter__ (self):
    return self.keys ()

  def copy (self):
    return dict (self.items ())

  cdef size_t _hash (ProxyDict self):
    cdef size_t ret

    ret = 0x3fc01436
    for key in self:
      ret = _mix_hash (ret, _xhash (key, self.tkeys.proxy.hash_seed))

    return ret

  def __hash__ (self):
    return (<ProxyDict>self)._hash ()

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
    return "ProxyDict(%s)" % self

  cdef Py_ssize_t _mut_vidx (self, key, unsigned int *codep) except -1:
    cdef const unsigned int *iarray
    cdef const unsigned long long *qarray
    cdef size_t ix, hv
    cdef Py_ssize_t mi

    hv = _xhash (key, self.tkeys.proxy.hash_seed)

    if not self.wide:
      iarray = <const unsigned int *>self.hashes
      ix = _find_hidx (iarray, hv, self.tkeys.size)
      ix = _find_obj_by_hidx (iarray, ix, key, self.tkeys)
    else:
      qarray = <const unsigned long long *>self.hashes
      ix = _find_hidx (qarray, hv, self.tkeys.size)
      ix = _find_obj_by_hidx (qarray, ix, key, self.tkeys)

    if ix == 0:
      raise KeyError ("cannot set new key in proxy dict")

    return self.tvalues._mut_idx (<Py_ssize_t>ix - 1, codep)

  def __setitem__ (self, key, val):
    cdef Py_ssize_t mi
    cdef unsigned int code

    mi = self._mut_vidx (key, &code)
    _builtin_write (self.tvalues.proxy.base + mi, val, code)

  def atomic_cas (self, key, exp, nval):
    cdef Py_ssize_t mi
    cdef unsigned int code

    mi = self._mut_vidx (key, &code)
    return _builtin_acas (self.tvalues.proxy.base + mi, exp, nval, code)

  def atomic_add (self, key, val):
    cdef Py_ssize_t mi
    cdef unsigned int code

    mi = self._mut_vidx (key, &code)
    return _builtin_aadd (self.tvalues.proxy.base + mi, val, code)

#####################################

cdef class ProxyDescrBuiltin:
  cdef Proxy proxy
  cdef void *ptr
  cdef unsigned int code

  @staticmethod
  cdef ProxyDescrBuiltin _make (Proxy proxy, void *ptr, unsigned int code):
    cdef ProxyDescrBuiltin ret

    ret = ProxyDescrBuiltin.__new__ (ProxyDescrBuiltin)
    ret.proxy = proxy
    ret.ptr = ptr
    ret.code = code
    return ret

  def __get__ (self, obj, cls):
    if obj is None:
      return self
    elif self.proxy.rdwr:
      atomic_fence_acq ()

    return _builtin_read (self.ptr, self.code)

  def _assert_writable (self):
    if not self.proxy.rdwr:
      raise TypeError ("cannot modify attribute of read-only object")

  def __set__ (self, obj, value):
    self._assert_writable ()
    _builtin_write (self.ptr, value, self.code)

  def add (self, value):
    self._assert_writable ()
    return _builtin_aadd (self.ptr, value, self.code)

  def cas (self, exp, nval):
    self._assert_writable ()
    return _builtin_acas (self.ptr, exp, nval, self.code)

cdef class ProxyDescrAny:
  cdef Proxy proxy
  cdef size_t offset

  @staticmethod
  cdef ProxyDescrAny _make (Proxy proxy, void *ptr):
    cdef ProxyDescrAny ret

    ret = ProxyDescrAny.__new__ (ProxyDescrAny)
    ret.proxy = proxy
    ret.offset = <size_t>(<char *>ptr - proxy.base)
    return ret

  def __get__ (self, obj, cls):
    if obj is None:
      return self

    return self.proxy._unpack (self.offset)

cdef inline str _decode_str (Proxy proxy, size_t off, size_t size):
  proxy._assert_len (off + size)
  return PyUnicode_FromStringAndSize (proxy.base + off, size)

cdef str _read_secret (Proxy proxy, size_t *offp):
  cdef size_t off, size
  cdef str val, md
  cdef unsigned int md_len
  cdef Py_ssize_t ix

  off = offp[0]
  if proxy.import_key is not None:
    proxy._assert_len (off + sizeof (md_len))
    memcpy (&md_len, proxy.base + off, sizeof (md_len))
    md = _decode_str (proxy, off + sizeof (md_len), md_len)
    off += md_len + sizeof (md_len)

  off = _read_uleb128 (proxy, off, &size)
  val = _decode_str (proxy, off, size)
  if (proxy.import_key is not None and
      md != HMAC(proxy.import_key, _encode_str (val),
                 _HASH_METHOD).hexdigest ()):
    raise ValueError ("import signature mismatch")

  offp[0] = off + size
  return val

cdef object _fetch_type (str module, str name):
  cdef object ret

  try:
    return getattr (Import_Module (module), name)
  except AttributeError:
    if module == 'builtins':
      ret = _BUILTINS_MAP.get (name)
      if ret is not None:
        return ret
    raise

cdef object _read_type (Proxy proxy, size_t *offp):
  cdef str path
  cdef Py_ssize_t ix

  path = _read_secret (proxy, offp)
  ix = path.rfind (".")

  if ix < 0:
    raise ValueError ("got an invalid typename %r" % path)

  return _fetch_type (path[:ix], path[ix + 1:])

cdef object _proxy_obj (Proxy proxy, size_t off):
  cdef Py_ssize_t ix
  cdef unsigned int code
  cdef void *ptr

  typ: type = _read_type (proxy, &off)
  attrs: ProxyDict = proxy._unpack (off)
  values: ProxyList = attrs.tvalues
  descrs: dict = {}

  for ix in range (len (values)):
    ptr = values._c_ptr (ix, &code)
    if not _is_inline_code (code):
      val = ProxyDescrAny._make (proxy, ptr)
    else:
      val = ProxyDescrBuiltin._make (proxy, ptr, code)

    descrs[str (attrs.tkeys._c_index (ix))] = val

  typ = type ("ProxyObject", (typ,), descrs)
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
  return _partial (_register_impl, typ, direction.PACK)

def register_unpack (typ):
  """
  Decorator used to register an unpacking function for the specified type.
  """
  return _partial (_register_impl, typ, direction.UNPACK)

cdef object _dispatch_type_impl (dict packers, typ, unsigned int ix):
  cdef list flist, val
  cdef size_t dist

  flist = packers.get (typ)
  if flist:
    rv = flist[ix]
    if rv:
      return rv

  dist = ~(<size_t>0)
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

def pack (obj, **kwargs):
  """
  Return a bytearray with the serialized representation of ``obj``.
  The keyword arguments are the same as those used in ``Packer.__init__``.
  """
  cdef Packer p
  cdef bytearray ret

  p = Packer (**kwargs)
  p.pack (obj)
  ret = p.wbytes
  PyByteArray_Resize (ret, p.wlen)
  return ret

def pack_into (obj, place, offset = None, **kwargs):
  """
  Pack an object at a specific offset in a destination.

  :param obj: The object to be serialized.

  :param place: The object in which to serialize it. This object may be
    a bytearray, or any object that implements the methods ``write`` and
    ``seek`` (in case the specified offset is not None).

  :param offset *(default None)*: The offset at which to serialize the object.
    If None, the object will be serialized at the destination's current
    position, if it applies.

  See ``Packer.__init__`` for information about the supported keyword args.
  """
  cdef bytearray b, bp

  b = pack (obj, offset = offset or 0, **kwargs)
  fn = getattr (place, "write", _SENTINEL)
  if fn is not _SENTINEL:
    if offset is None:
      return fn (b)

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
    with which a ``Proxy`` can be built.

  :param int offset *(default 0)*: The offset inside the source at which
    to unpack.

  See ``Proxy.__init__`` for information about the supported
    keyword args.
  """
  return Proxy(place, offset, **kwargs).unpack ()

cpdef unproxy (obj):
  """
  Convert any proxied object into its materialized counterpart, recursively.
  i.e: a ProxyList is turned into a regular Python list.
  """
  if isinstance (obj, ProxyStr):
    return _PyUnicode_Copy ((<ProxyStr>obj).uobj)
  elif isinstance (obj, ProxySet):
    return (<ProxySet>obj)._toset ()
  elif isinstance (obj, ProxyDict):
    return (<ProxyDict>obj)._todict ()
  elif isinstance (obj, ProxyList):
    return (<ProxyList>obj)._unproxy ()
  return obj

def _pack_module (packer, obj):
  packer.write_secret (obj.__name__)

def _unpack_module (cls, proxy, off):
  return Import_Module (proxy.read_secret (off))

def _pack_function (packer, obj):
  packer.write_secret (obj.__module__ + '.' + obj.__name__)

def _unpack_function (cls, proxy, off):
  rs = proxy.read_secret (off)
  ix = rs.index ('.')
  module, name = rs[:ix], rs[ix + 1:]
  ret = getattr (Import_Module (module), name)

  if not isinstance (ret, cls):
    raise TypeError ('attribute %s of module %s is not a function' %
                     (module, name))
  return ret

_register_impl (types.ModuleType, direction.PACK, _pack_module)
_register_impl (types.ModuleType, direction.UNPACK, _unpack_module)

_register_impl (types.FunctionType, direction.PACK, _pack_function)
_register_impl (types.FunctionType, direction.UNPACK, _unpack_function)

_register_impl (types.BuiltinFunctionType, direction.PACK, _pack_function)
_register_impl (types.BuiltinFunctionType, direction.UNPACK, _unpack_function)

# Exported typecodes.
TYPE_INT8 = tpcode.INT8
TYPE_INT16 = tpcode.INT16
TYPE_INT32 = tpcode.INT8
TYPE_INT64 = tpcode.INT16
TYPE_FLOAT32 = tpcode.FLOAT32
TYPE_FLOAT64 = tpcode.FLOAT64
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
