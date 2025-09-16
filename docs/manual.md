## *zser* --- Fast, zero-copy serialization

This library allows users to pack arbitrary objects into a binary stream,
and to unpack them a bit differently than typical serialization libraries:
Instead of returning the original object, **zser** returns an object
that masquerades it, implementing the same interface (with a few caveats), but
using far less resources (i.e: time and memory) to perform this unpacking.

Any object that implements Python's buffer protocol can be used as a destination
to perform the packing and unpacking.

When manipulating objects, these are split into two kinds: Primitives, which
are stored inline and retrieved as such, like most serialization libraries do.
Primitives include numeric types like **int** and **float**.

The other kind, compound objects, work a bit differently. When unpacking them,
an indirect object (or **proxy**) is returned, which is what makes this operation
fast. Proxy objects act as lazy containers, and their underlying sub-objects
are recreated on demand, instead of upfront. We strive to support the same
interface for proxies as that of the original types.

With some restrictions, users may also write into proxied objects, and the
underlying backing will reflect those changes as well. So **zser** can be used
as a way share data, and communicate changes as well.

## Supported types

All of Python builtin types are supported, with the exception of functions and
modules, which are a bit tricky to handle. Any user-defined type that is
implemented in Python is also fully supported, but extension types are not.

It should be noted that **zser** allows users to customize the way unsupported
types are managed, so users can fully overcome the initial limitations of the
library.

As mentioned before, **zser** may not return the original objects that were
packed, but rather a proxy object. The mapping table is thus:

|  Python type   |   Proxy type    |
|:--------------:|:---------------:|
| list           |   ProxyList     |
| tuple          |   ProxyList     |
| str            |   ProxyStr      |
| set            |   ProxySet      |
| frozenset      |   ProxySet      |
| dict           |   ProxyDict     |
| other          |   ProxyObject   |

## Portability

The library does not guarantee any kind of portability of the binary format used
for objects, _except_ for platforms with identical endianness and word size.
Therefore, it is recommended to only share binary files among systems of the
same architecture, or among systems that fulfill the above requirement - For
example, binary files _should_ be shareable between x86-64 and aarch64 systems.

## Classes

```python
class Packer (offset = 0, id_cache = None, hash_seed = 0,
              custom_packers = None, initial_size = 8, import_key = None)
```

  Returns an object capable of producing the binary representation of arbitrary
  objects. Instances of this class generate byte arrays which can then be
  written into output objects. The constructor parameters are as following:

  * offset: The starting offset at which the objects will be serialized in the output.
  * id_cache: A dictionary that maps objects id to offsets. Necessary to correctly serialize
              cyclical objects.
  * hash_seed: An integer that is used to mix the hash values of the serialized objects
               when needed. This can be used in order to prevent malicious users from
               generating pathological cases with hand-crafted hash values.
  * custom_packers: A dict that maps custom types to their serializing functions. If
                    *None*, the current global map will be copied and used.
  * initial_size: The initial size of the byte array used to serialize objects into.
  * import_key: A bytes or string object that is used to compute the checksum used when
                serializing custom objects. Since these objects may need to import modules
                in order to deserialize them, and since the import process may execute
                arbitrary code, this key can be used to prevent against malicious input.

  ```python
    resize (extra)
  ```

  Increases the packer's capacity in _extra_ bytes.

  ```python
    bump (nbytes)
  ```

  Bumps the packer's internal offset in _nbytes_ bytes.

  ```python
    putb (bx)
  ```

  Writes the single byte _bx_ into the packer's stream.

  ```python
    zpad (nbytes)
  ```

  Write _nbytes_ zeroes into the packer's stream.

  ```python
    align_to (size)
  ```

  Ensures the packer's current position is aligned to _size_ bytes by padding
  with zeroes, if needed.

  ```python
    pack_struct (format, *args)
  ```

  Same as calling *struct.pack_into* with the packer's stream and offset as output.

  ```python
    pack_struct_at (format, position, *args)
  ```
  Same as calling *struct.pack_into* with the packer's stream and *position* as output.

  ```python
    bwrite (obj)
  ```

  Writes _obj_ into the stream.

  ```python
    as_bytearray ()
  ```

  Returns a copy of the packer's byte stream.

  ```python
    pack (obj)
  ```

  Packs an object into the packer's stream.

```python
class Proxy (mapping, offset = 0, size = None, rw = False,
             hash_seed = 0, verify_str = False, import_key = None)
```

  Returns an object that manages a mapping so that objects can be deserialized out of it.
  A Proxy is responsible for creating all the proxy objects out of mappings.
  Its constructor parameters are as following:

  * mapping: The object that backs the mapping. If this object has a _fileno_ method, this
             object will be assumed to be a file, and its file descriptor will be used to
             construct the mapping via **mmap**. Otherwise, a **memoryview** will be
             made out of this object.
  * offset: The starting offset for the mapping object.
  * size: The maximum size to be used for the mapping. If _None_, no size limits will be
          assumed for the mapping.
  * rw: Whether the mapping is read-write. If _True_, and the mapping supports it, some
        mutations will be allowed. If _True_, but the mapping doesn't support it, a
        **BufferError** will be raised.
  * hash_seed, import_key: See the **Packer** constructor for details.
  * verify_str: Whether to check for strings' consistency when unpacking them.
  
  ```python
    __len__ ()
  ```

  Returns the Proxy's mapping size.

  ```python
    __getbuffer__ (buf, flags)
    __releasebuffer__ (buf)
  ```

  Buffer interface implementation for Proxy.

  ```python
    unpack_struct (format, offset)
  ```

  Same as calling *struct.unpack_from* with the mapping and offset as inputs.

  ```python
    struct_size (format)
  ```

  Same as calling *struct.calcsize* with _format_ as argument.

  ```python
    __getitem__ (index)
  ```

  Returns the byte at position _index_ for the mapping.

  ```python
    unpack ()
  ```

  Unpacks an object at the Proxy's current position and returns it.

  ```python
    unpack_from (offset)
  ```

  ```python
    unpack_as (typecode, offset = None)
  ```

  Unpacks an object of type _typecode_. If _offset_ is not _None_, the unpacking is done
  at that position; otherwise, it's unpacked at the current offset. See below for the
  constants that may be used for the typecode.

```python
class ProxyList
```

  The indirect form of a builtin **list**, constructed by a **Proxy** out of a mapping.
  Instances of this class behave like a Python list, with the following exceptions:

  * A ProxyList is only mutable (i.e: Its elements can be set) iff the underlying mapping
    is read-write, and if the element to be modified is primitive (integer or float).
  * The size of a ProxyList cannot be modified, even if it's mutable. This means that the
    following interfaces are not available: _append_, _clear_, _extend_, _insert_, _pop_,
    _remove_, _reverse_. The method _sort_ is also not available.
  * A ProxyList implements 2 methods not present in regular lists, specified below:

  ```python
    atomic_cas (index, expected, new)
  ```

  Atomically compares the value of the list at position _index_, and if it's identical to
  _expected_, sets it to _new_. This method only works if the list is mutable. Returns
  _True_ if the operation succeeded; _False_ otherwise.

  ```python
    atomic_add (index, value)
  ```

  Atomically adds _value_ to the element in the ProxyList at position _index_. This
  method only works if the list is mutable. Returns the previous element at the specified
  position.

```python
class ProxyStr
```

  Indirect form of a builtin **str**. Implements the same interface.

```python
class ProxySet
```

  Indirect form of a builtin **frozenset**. Instances of this class are always immutable,
  which means that the following interfaces are not available: _add_, _clear_, _pop_,
  _remove_, _update_.

```python
class ProxyDict
```

  Indirect form of a builtin **dict**. Instances of this class are normally immutable,
  with the following exceptions:

  * The ProxyDict was constructed out of a mutable **Proxy**.
  * The value being mutated is a primitive type (integer or float).

  If both conditions are met, then a **ProxyDict** can safely call the __setitem__
  method to modify its values. In addition, the following 2 methods not present in
  regular dicts are present in a **ProxyDict**:

  ```python
  atomic_cas (key, expected, new)
  ```

  ```python
  atomic_add (key, value)
  ```

  These work similarly to the **ProxyList** methods of the same name, with the exception
  that instead of an index, they take a key to reference the value to be modified.

  Every other method present in a **dict** that may cause modifications to its underlying
  structure is not supported by a **ProxyDict**. That means that the following interfaces
  are not available: _clear_, _pop_, _popitem_, _update_. In addition, since a **ProxyDict**
  is constructed out of a **Proxy**, the class method _fromkeys_ is not implemented.

## Custom objects

When a user-defined class is packed and then unpacked, **zser** dynamically creates a proxy
class to masquerade it. Instances of this newly created class implements the same methods
and have the same properties of the original object, with the following caveats:

  * The object's slots are implemented as descriptors that access the data via a Proxy.
  * The object's slots can be mutated iff the the underlying mapping is mutable, and if
    their type is primitive (integer or float)
  * The descriptors that implement the object's slots have 2 additional methods: **cas** and
    **add** that can be used to *atomically* modify their values. They can be used as such:

  ```python
    x = myclass (value = 1)   # Create object with slot named 'value'
    proxy = zser.unpack_from (zser.pack (x), rw = True)
    type(proxy).value.add (-1)     # Atomically adds -1 to proxy's value
    type(proxy).value.cas (0, 2)   # Atomic CAS on proxy's value
  ```

## Module functions

```python
def xhash (obj, seed = 0)
```

Compute the hash code for object _obj_, using _seed_ as the starting value.
The return value is stable across different processes, and is unaffected by
environment variables and any other external parameters. Supported types are
the following: **int**, **float**, **str**, **frozenset**, **tuple** and all proxies.

```python
def register_pack (type)
```

Registers a packing routine for the specified type. Once registered, if a **Packer**
encounters an object of this type, the function will be called with the packer
as its first argument, and the object as the second one. For example:

  ```python
  class Foo:
    pass

  @zser.register_pack (Foo)
  def pack_foo (packer, obj):
    # Pack a Foo object using the packer.
  ```

```python
def register_unpack (type)
```
Registers an unpacking routine for the specified type. Once registered, if a proxy
container encounters the specified type, the function will be called with 3 arguments:
The type of the object that should be unpacked, the **Proxy** and the offset at which
the unpacking takes place. For example:

  ```python
  class Foo:
    pass

  @zser.register_unpack (Foo)
  def unpack_foo (cls, handler, offset):
    # Unpack a Foo object using the proxy_handler and offset.
  ```

```python
def pack (obj, **kwargs)
```

Returns the binary representation of the object as a bytearray. Equivalent to
creating a **Packer** with the passed keyword arguments, calling _pack_ with
the passed object and then returning the value of calling _as_bytearray_.

```python
def pack_into (obj, place, offset = None, **kwargs)
```

Packs an object at a specific offset in the destination. The parameter _place_
can be a bytearray, in which case the object will be written at the specified
offset (or concatenated, if _offset_ is None). Otherwise, _place_ must
implement a method, _write_, which will be called with the packed object,
and _seek_, if the offset is not _None_, in order to write the object at the
specified offset (i.e: Like a file does). Returns the number of bytes written.

```python
def unpack_from (place, offset = 0, **kwargs)
```

Unpacks an object from the specified input and from an offset. The keyword arguments are
used to construct a **Proxy**. See its documentation for a description of the parameters.

```python
def unpack_as (place, code, offset = 0, **kwargs)
```

Unpacks an object from the specified input, and with the specified typecode and offset.
The typecode can be one of the following module constants:
  * TYPE_INT8: Signed 8-bit integer.
  * TYPE_INT16: Signed 16-bit integer.
  * TYPE_INT32: Signed 32-bit integer.
  * TYPE_INT64: Signed 64-bit integer.
  * TYPE_FLOAT32: 32-bit floating point type.
  * TYPE_FLOAT64: 64-bit floating point type.
  * TYPE_BIGINT: Arbitrary precision number
  * TYPE_NONE, TYPE_TRUE, TYPE_FALSE: The constants _None_, _True_, _False_
  * TYPE_BACKREF: A reference to an object that was previously serialized
  * TYPE_STR, TYPE_BYTES, TYPE_BYTEARRAY, TYPE_LIST, TYPE_TUPLE, TYPE_SET, TYPE_DICT: Self-explanatory
  * TYPE_OBJECT: Any object of a type not specified

```python
def unproxy (obj)
```

Converts a proxy object (**ProxyList**, **ProxyStr**, **ProxySet**, **ProxyDict**)
into its 'regular' counterpart, recursively.
