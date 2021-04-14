import zser
import os
import struct
import pytest

from tempfile import TemporaryFile, NamedTemporaryFile

def tst_equality (obj):
  for i in range (7):
    assert obj == zser.unpack_from (zser.pack (obj, offset = i), offset = i)

def test_equal_int ():
  tst_equality (-1)
  tst_equality (1)
  tst_equality (-(1 << 32))
  tst_equality (1 << 32)
  tst_equality (-(1 << 63))
  tst_equality (1 << 63)
  tst_equality ((1 << 100) | (1 << 52) | (1 << 13))
  tst_equality (-((1 << 92) | (1 << 47) | (1 << 7)))

def test_equal_flt ():
  tst_equality (3.14)
  tst_equality (-6.2e-4)
  tst_equality (-1825.49)
  tst_equality (float (1 << 40))

def test_equal_str ():
  tst_equality ("_" * 1000)
  tst_equality (chr (130) * 6)
  tst_equality (chr (1001) * 24)
  tst_equality (chr (0x10001) * 16)

def test_equal_list_int ():
  tst_equality ([i for i in range (1000)])

def test_equal_list_flt ():
  tst_equality ([i + 3.14 for i in range (1000)])

def test_equal_list_str ():
  tst_equality (["@" + str (i) + "!" for i in range (1000)])

def test_equal_list_many ():
  lst = []
  append = lst.append
  for i in range (1000):
    append (i)
    append (i + 3.14)
    append ("@" + str (i) + "!")

  tst_equality (lst)

def test_equal_set_int ():
  tst_equality (set (i for i in range (1000)))

def test_equal_set_flt ():
  tst_equality (set (i + 3.14 for i in range (1000)))

def test_equal_set_str ():
  tst_equality (set ("@" + str (i) + "!" for i in range (1000)))

def test_equal_set_many ():
  s = set ()
  add = s.add
  for i in range (1000):
    add (i)
    add (i + 3.14)
    add ("@" + str (i) + "!")

  tst_equality (s)

def test_equal_dict_int ():
  tst_equality ({i: -i for i in range (1000)})

def test_equal_dict_flt ():
  tst_equality ({i + 3.14: -(i + 3.14) for i in range (1000)})

def test_equal_dict_str ():
  d = {}
  for i in range (1000):
    k = "@" + str (i) + "!"
    v = "!" + str (i) + "@"
    d[k] = v

  tst_equality (d)

def test_equal_dict_many ():
  d = {}
  for i in range (1000):
    d[i] = -i
    d[i + 3.14] = -(i + 3.14)
    d["@" + str (i) + "!"] = "!" + str (i) + "@"

  tst_equality (d)

def tst_unpack_as (obj, code):
  bx = zser.pack (obj)
  assert obj == zser.unproxy (zser.unpack_as (bx, code, 1, rw = True))
  p = zser.packer ()
  p.pack (obj, tag = False)
  bx = p.as_bytearray ()
  assert obj == zser.unproxy (zser.unpack_as (bx, code, rw = True))

def test_unpack_as ():
  for obj, code in ((-1, zser.TYPE_INT), (104, zser.TYPE_UINT),
                    (44.55, zser.TYPE_FLOAT), (1 << 100, zser.TYPE_BIGINT),
                    ("???_*!az", zser.TYPE_STR), (b"13345", zser.TYPE_BYTES),
                    (bytearray (b"abc000"), zser.TYPE_BYTEARRAY),
                    ([44, -5.2, "abc"], zser.TYPE_LIST),
                    ((b"!!!!", 777), zser.TYPE_TUPLE),
                    (None, zser.TYPE_NONE), (True, zser.TYPE_TRUE),
                    (False, zser.TYPE_FALSE),
                    (set ([3, 1, 2]), zser.TYPE_SET),
                    ({"a": 1, (3.14, 100): ""}, zser.TYPE_DICT)):
    tst_unpack_as (obj, code)

# Proxy list API

def tst_plist_atomic (mul):
  lst = list (x * mul for x in (1, 2, 3))
  q = zser.unpack_from (zser.pack (lst), rw = True)

  q.atomic_add (1, -lst[1])
  assert q[1] == 0
  assert q[0] == lst[0]
  assert q[2] == lst[2]

  assert q.atomic_cas (1, 0, lst[1] * 3)
  assert q[0] == lst[0]
  assert q[2] == lst[2]
  assert q[1] == lst[1] * 3

  assert not q.atomic_cas (1, -1, 0)
  with pytest.raises (IndexError):
    q.atomic_add (len (q), 0)

  # Test unsupported types.
  q = zser.unpack_from (zser.pack (["abc"]))
  with pytest.raises (TypeError):
    q.atomic_add (0, "def")

def tst_plist_type (obj, rw, typ):
  q = zser.unpack_from (zser.pack (obj), rw = rw)
  assert type (zser.unproxy (q)) is typ

def test_plist_api ():
  p = zser.packer ()
  lst = []
  append = lst.append

  for i in range (1000):
    append (i)
    append (-(i + 5000))
    append ((i + 7.5) ** 1.6)
    append ("__" + str (i * 3) + "!!!")
    append (i)

  q = zser.unpack_from (zser.pack (lst))

  for i1, i2, step in ((92, 213, 3), (173, 366, 4), (352, 65, -2)):
    assert lst[i1:i2:step] == q[i1:i2:step]
    assert lst[i1:i2:step][::-2] == q[i1:i2:step][::-2]

  assert lst[len (lst) // 2] == q[len (q) // 2]
  assert lst.index (999) == q.index (999)
  assert 999 in q
  assert lst.count (1) == q.count (1)
  assert lst == zser.unpack_from(zser.pack (lst), rw = True).copy ()
  assert tuple (lst) == q.copy ()

  with pytest.raises (ValueError):
    q.index ("...")

  assert q.count ("...") == 0
  assert q <= q
  assert q >= q
  assert q == q

  last = lst.pop (-1)
  assert q > lst
  assert q >= lst
  assert lst < q
  assert lst <= q

  lst.append (last)
  lst.append (lst)
  assert q < lst
  assert q <= lst
  assert lst > q
  assert lst >= q

  lst.pop (-1)
  assert list (q + q) == lst + lst

  for x in (1, -1, 1.5):
    tst_plist_atomic (x)

  # Mutability checks.
  tst_plist_type ([1, 2], False, tuple)
  tst_plist_type ((1, 2), False, tuple)
  tst_plist_type ([1, 2], True, list)
  tst_plist_type ((1, 2), True, tuple)

  # Test unsupported writes.
  q = zser.unpack_from (zser.pack (["abc"]), rw = True)
  with pytest.raises (TypeError):
    q[0] = -1

# Proxy string API

def test_pstr_api ():
  s = "abcdefghijklmnopqrstuvwxyz0123456789" * 13
  q = zser.unpack_from (zser.pack (s))

  for i1, i2, step in ((10, 19, 2), (3, 29, 5), (-4, 8, -2), (1, 6, 1),
                       (0, 100, 1), (100, 100, 1), (100, 0, 1)):
    assert s[i1:i2:step] == q[i1:i2:step]
    assert s[i1:i2:step][::-1] == q[i1:i2:step][::-1]

  assert "stuvw" in q
  assert q.index ("0123") == s.index ("0123")
  with pytest.raises (ValueError):
    q.index ("???")

  assert len (q) == len (s)
  assert hash (q) == hash (s)
  assert q <= s
  assert q >= s
  assert q < s + "_"
  assert q <= s + "?"
  assert q + "_" > s
  assert q + "?" >= s

  # Make sure no segfaults when deallocating proxy string
  del q
  q = zser.unpack_from (zser.pack (s))

  assert q.encode ("utf-8") == s.encode ("utf-8")

  # Test that non-ASCII strings are correctly (un)packed.
  s = "abcdef" + chr (0x1000) + "???"
  q = zser.unpack_from (zser.pack (s))
  assert s == q

  s += chr (0x10001) + "..."
  q = zser.unpack_from (zser.pack (s))
  assert s == q

  # Test for correctness when the input string is corrupted.
  bx = zser.pack ("abcdef")
  bx[bx.find (ord ("e"))] = 0x80
  with pytest.raises (ValueError):
    zser.unpack_from (bx, verify_str = True)

  s = 'abc123%d'
  q = zser.unpack_from (zser.pack (s))
  assert (s % -1) == (q % -1)
  assert (s * 3) == (q * 3)

# Proxy set API

def _tst_pset_sorted (mul):
  s1 = set (x * mul for x in range (1, 1000))
  s2 = set (x * mul for x in range (500, 1000))

  q1 = zser.unpack_from (zser.pack (s1))
  q2 = zser.unpack_from (zser.pack (s2))

  assert (q1 | q2) == (s1 | s2)
  assert (q1 & q2) == (s1 & s2)
  assert (q1 - q2) == (s1 - s2)
  assert (q1 ^ q2) == (s1 ^ s2)
  assert not (q1 - q1)
  assert q1 <= s1
  assert q2 <= s2
  assert q2 < q1
  assert q2 <= q1
  assert q1 > q2
  assert q1 >= q2

def test_pset_api ():
  _tst_pset_sorted (1)
  _tst_pset_sorted (-1)
  _tst_pset_sorted (2.3)

  l1 = []
  append = l1.append
  for i in range (1000):
    append (i)
    append (-(i + 2000))
    append (i + 3.14)
    append (str (i) + "???")

  l2 = l1[:int (len (l1) * 0.4)]
  s1, s2 = set (l1), set (l2)

  q1 = zser.unpack_from (zser.pack (s1))
  q2 = zser.unpack_from (zser.pack (s2))

  assert None not in q1
  assert None not in q2

  assert (q1 | q2) == (s1 | s2)
  assert (q1 & q2) == (s1 & s2)
  assert (q1 - q2) == (s1 - s2)
  assert (q1 ^ q2) == (s1 ^ s2)
  assert not (q1 - q1)
  assert q1 <= s1
  assert q2 <= s2
  assert q2 < q1
  assert q2 <= q1
  assert q1 > q2
  assert q1 >= q2

# Proxy dict API

def test_pdict_api ():
  lst = []
  append = lst.append
  for i in range (1000):
    append ((i, i + 3.14))
    append ((str (i) + "???", -(i + 2000)))

  d = dict (lst)
  q = zser.unpack_from (zser.pack (d))
  assert "501???" in q
  assert 977 in q
  assert q[65] == 65 + 3.14
  assert q.get (None) is None
  assert q.get (None, -1) == -1

  with pytest.raises (KeyError):
    q[1001]

  def pair_key (pair):
    elem = pair[0]
    if not isinstance (elem, int):
      return hash (elem)
    return elem

  items = list (q.items ())
  items.sort (key = pair_key)
  lst.sort (key = pair_key)
  assert items == lst

# Custom object API

class CustomWithDict:
  def __init__ (self, x, y, z):
    self.x, self.y, self.z = x, y, z

  def fn (self):
    return (self.z, self.x, self.y)

  def __eq__ (self, x):
    return self.fn () == x.fn ()

class CustomWithSlots:
  __slots__ = "a", "b1", "cxx", "d_"
  
  def __init__ (self, a, b, c, d):
    self.a = a
    self.b1 = b
    self.cxx = c
    self.d_ = d

  def fx (self, elem):
    return [elem] + [self.a, self.b1, self.cxx, self.d_]

def test_custom ():
  c1 = CustomWithDict (1, 3.14, "abc")
  q = zser.unpack_from (zser.pack (c1))
  assert q.fn () == c1.fn ()

  c2 = CustomWithSlots (66, -999.4, ["??????"], None)
  q = zser.unpack_from (zser.pack (c2))
  assert q.fx (1) == c2.fx (1)

def test_backref ():
  c1 = CustomWithDict (-1, 1, .5)
  bx = bytearray (256)
  lst = [c1, "abc???", None]
  lst[-1] = lst
  zser.pack_into (lst, bx, offset = 0)

  q = zser.unpack_from (bx, rw = True)
  q[0].x = -33
  assert q[-1][0].x == q[0].x

def tst_atomic (value):
  c = CustomWithDict (None, value, [])
  q = zser.unpack_from (zser.pack (c))

  with pytest.raises (TypeError):
    type(q).y.add (value)

  q = zser.unpack_from (zser.pack (c), rw = True)
  assert type(q).y.cas (value, -value)
  assert q.x is None
  assert q.z == []
  assert type(q).y.add (value) == -value
  assert q.y == 0

def test_atomic ():
  tst_atomic (-1)
  tst_atomic (1 << 31)
  tst_atomic (3.14)

# Registration API

class Registered:
  def __init__ (self, a1, a2):
    self.a1 = a1
    self.a2 = a2

  def f (self):
    return [self.a2, self.a1]

@zser.register_pack (Registered)
def pack_obj (pk, obj):
  tmp = pk.copy ()
  size = tmp.pack (obj.a1)
  pk.pack_struct ("N", size)
  pk.bwrite (tmp)
  pk.pack (obj.a2)

@zser.register_unpack (Registered)
def unpack_obj (cls, handler, off):
  size = handler.unpack_struct ("N", off)[0]
  off += handler.struct_size ("N")
  a1 = handler.unpack_from (off)
  off += size
  a2 = handler.unpack_from (off)
  return cls (a1, a2)

def test_register ():
  reg = Registered ("abc", -66.9)
  q = zser.unpack_from (zser.pack (reg))
  assert reg.f () == q.f ()

# Test poisoned inputs

def tst_too_short (obj):
  bx = zser.pack (obj)
  for i in range (1, 4):
    with pytest.raises (ValueError):
      str (zser.unpack_from (bx[:-i]))

def test_poisoned ():
  for x in (1, 3.14, -123, "abcdef", ["qx", 1], (101, 69, 15 << 3),
            set ([-44, 101]), set (["87323", 5.6]), {"rn": 1, -2.6: ()}):
    tst_too_short (x)

def test_signature ():
  ikey = "passwd"
  cx = CustomWithDict ("????", 42.5, -66)
  bx = zser.pack (cx, import_key = ikey)
  c2 = zser.unpack_from (bx, import_key = ikey)
  assert c2.fn () == cx.fn ()
  with pytest.raises (ValueError):
    zser.unpack_from (bx, import_key = ikey + "*")

def test_short_mview ():
  buf = zser.pack (100)
  for i in range (1, 7):
    with pytest.raises (ValueError):
      zser.unpack_from (buf, 0, size = len (buf) - i)

# Test large offsets

LARGE_SIZE = 0x4000000

def tst_large_array_cnum (value):
  ax = [value] * LARGE_SIZE
  assert ax == zser.unpack_from (zser.pack (ax))

def test_large_array_any ():
  elem_1 = "a" * (LARGE_SIZE // 2)
  elem_2 = "b" * (LARGE_SIZE // 2)
  ax = [elem_1, 3.14, elem_2, None]
  assert ax == zser.unpack_from (zser.pack (ax))

def tst_large_set_cnum (off):
  s = set (i + off for i in range (LARGE_SIZE // struct.calcsize ("N")))
  assert s == zser.unpack_from (zser.pack (s))

def _test_large_set_cnum ():
  tst_large_set_cnum (0)
  tst_large_set_cnum (-LARGE_SIZE * 2)
  tst_large_set_cnum (1.0)

def test_large_set_any ():
  elem_1 = "a" * (LARGE_SIZE // 2)
  elem_2 = "b" * (LARGE_SIZE // 2)
  s = set ([elem_1, elem_2, 3.14, None])
  assert s == zser.unpack_from (zser.pack (s))

def test_large_dict ():
  key_1 = "a" * (LARGE_SIZE // 2)
  key_2 = "b" * (LARGE_SIZE // 2)
  d = { key_1: -3.14, key_2: [1, None]}
  assert d == zser.unpack_from (zser.pack (d))

def test_large_generic ():
  g = CustomWithDict (1, 3.14, "a" * LARGE_SIZE)
  q = zser.unpack_from (zser.pack (g))
  assert g.x == q.x
  assert g.y == q.y
  assert g.z == q.z

# Test file API

def tst_file (obj):
  with TemporaryFile () as f:
    f.truncate (0)
    for i in range (8):
      zser.pack_into (obj, f, i)
      f.seek (0, 0)
      assert zser.unpack_from (f, i) == obj

def test_file ():
  for x in (-415, 1 << 32, 173.5, "abcdef",
            (1, 2, 3), (1.3, 5.5), (65, "...?_", 3.2),
            {100, 50, 75}, {"string", 6.4, -10},
            {"key": "value", 1: -1.},
            CustomWithDict (None, True, False)):
    tst_file (x)

def test_persistent_changes ():
  with NamedTemporaryFile (delete = False) as f:
    path = f.name
    zser.pack_into ([0, 0, 0], f)
    f.seek (0, 0)
    q = zser.unpack_from (f, rw = True)
    q[0] = -1

  with open (path, "r+b") as f:
    q = zser.unpack_from (f)
    assert q[0] == -1
    os.remove (path)

