:mod:`zser` --- Fast, zero-copy serialization
=============================================

.. py:module:: zser
   :synopsis: Fast, zero-copy serialization

--------------

This library allows users to pack arbitrary objects into a binary
representation, and to unpack them a bit differently than typical serialization
libraries: Instead of returning the original object, `zser` returns an object
that masquerades it, implementing the same interface (with a few caveats), but
using far less resources (i.e: time and memory) to perform this unpacking.

Any object that implements Python's buffer protocol can be used as a destination
to perform the packing and unpacking.

When manipulating objects, these are split into two kinds: Primitives, which
are stored inline and retrieved as such, like most serialization libraries do.
Primitives include numeric types like `int` and `float`.

The other kind, compund objects, work a bit differently. When unpacking them,
an indirect object (or `proxy`) is returned, which is what makes this operation
fast. Proxy objects act as lazy containers, and their underlying sub-objects
are recreated on demand, instead of upfront. We strive to support the same
interface for proxies as that of the original types.

With some restrictions, users may also write into proxied objects, and the
underlying backing will reflect those changes as well. So `zser` can be used
as a way share data, and communicate changes as well.

Supported types
---------------

All of Python builtin types are supported, with the exception of functions and
modules, which are a bit tricky to handle. Any user-defined type that is
implemented in Python is also fully supported, but extension types are not.

It should be noted that `zser` allows users to customize the way unsupported
types are managed, so users can fully overcome the initial limitations of the
library.

As mentioned before, `zser` may not return the original objects that were
packed, but rather a proxy object. The mapping table is thus:

+----------------+-----------------+
|  Python type   |   Proxy type    |
+================+=================+
| list           |   proxy_list    |
+----------------+-----------------+
| tuple          |   proxy_list    |
+----------------+-----------------+
| str            |   proxy_str     |
+----------------+-----------------+
| set            |   proxy_set     |
+----------------+-----------------+
| frozenset      |   proxy_set     |
+----------------+-----------------+
| dict           |   proxy_dict    |
+----------------+-----------------+
| other          |   proxy_object  |
+----------------+-----------------+

Portability
-----------

The library does not guarantee any kind of portability of the binary format used for objects, *except*
for platforms with identical endianness and word size. Therefore, it is recommended to only share binary
files among systems of the same architecture, or among systems that fulfill the above requirement - For
example, binary files *should* be shareable between x86-64 and aarch64 systems.

Classes
-------

.. py:class:: packer (offset = 0, id_cache = None, hash_seed = 0, custom_packers = None, initial_size = 8, import_key = None)

   Returns an object capable of producing the binary representation of arbitrary objects. Instances of this class
   generate byte arrays which can then be written into output objects. The constructor parameters are as following:

   - *offset*: The starting offset at which the objects will be serialized in the output.
   - *id_cache*: A dictionary that maps objects id to offsets. Necessary to correctly serialize cyclical objects.
       If `None`, a new dict will be created and used.
   - *hash_seed*: An integer that is used to mix the hash values of the serialized objects when needed. This can
       be used in order to prevent malicious users from generating pathological cases with hand-crafted hash values.
   - *custom_packers*: A dict that maps custom types to their serializing functions. If `None`, the current global
       map will be copied and used.
   - *initial_size*: The initial size of the byte array used to serialize objects into.
   - *import_key*: A bytes or string object that is used to compute the checksum used when serializing custom
       objects. Since these objects may need to import modules in order to deserialize them, and since the import
       process may execute arbitrary code, this key can be used to prevent against malicious input.

  .. py:method:: copy()
    Returns a new packer that is a copy of the caller. Can be used to serialize complex objects without the
      need of modifying the current object.

  .. py:method:: resize (extra)

    Increases the packer's capacity in *extra* bytes.

  .. py:method:: bump (nbytes)

    Bumps the packer's internal offset in *nbybtes* bytes.

  .. py:method:: putb (bx)

    Write the single byte *bx* into the packer's stream.

  .. py:method:: zpad (nbytes)

    Write *nbytes* zeroes into the packer's stream.

  .. py:method:: align_to (size)

    Ensures the packer's current position is aligned to *size* bytes.

  .. py:method:: pack_struct (format, args...)

    Same as writing *struct.pack_into* with the packer's stream and offset as the output.

  .. py:method:: bwrite (object)

    Writes *object* into the stream. The object may be another packer, in which case its
    byte stream will be written.

  .. py:method:: as_bytearray ()

    Returns a copy of the packer's byte stream.

  .. py:method:: pack (object, tag = True)

    Packs an object into the packer's stream. If *tag* is True, also emits the object's typecode.

.. py:class:: proxy_handler (mapping, offset = 0, size = None, rw = False, hash_seed = 0, verify_str = False, import_key = None)

   Returns an object that manages a mapping so that objects can be deserialized out of it. A proxy_handler
   is responsible for creating all the proxy objects out of mappings. Its constructor parameters are as following:

   - *mapping*: The object that backs the mapping. If this object has a *fileno* method, this object will be assumed
       to be a file, and its file descriptor will be used to construct the mapping with *mmap*. Otherwise, a *memoryview*
       will be constructed out of this object.
   - *offset*: The starting offset for the mapping object.
   - *size*: The maximum size to be used for the mapping. If `None`, the full size will be assumed.
   - *rw*: Whether the mapping is read-write. If `True`, and the mapping supports it, modifications will be allowed,
       with some limitations. If `True`, but the mapping does not support it, a `BufferError` will be raised.
   - *hash_seed*, *import_key*: See the ``packer`` constructor for details.
   - *verify_str*: Whether to check for string's consistency when unpacking them.

  .. py:method:: __len__ (self)

    Return the proxy_handler's mapping size.

  .. py:method:: __getbuffer__ (self, buf, flags)

    Buffer interface implementation for proxy_handlers.

  .. py:method:: __releasebuffer__ (self, buf)

    Buffer interface implementation for proxy_handlers.

  .. py:method:: unpack_struct (self, format, offset)

    Same as calling ``struct.unpack_from`` with the mapping and offset as inputs.

  .. py:function:: struct_size (format)

    Same as calling ``struct.calcsize`` with *format* as argument.

  .. py:method:: __getitem__ (self, index)

    Return the byte at position *index* for the underlying mapping.

  .. py:method:: unpack (self)

    Unpacks an object at the proxy_handler's current position and returns it.

  .. py:method:: unpack_from (self, offset)

    Unpacks an object at position *offset* and returns it.

  .. py:method:: unpack_as (self, typecode, offset = None)

    Unpacks an object of type *typecode*. If *offset* is not `None`, the unpacking is done at that position;
    otherwise it's unpacked at position *offset*. See below for the constants that may be used for the typecode.

.. py:class:: proxy_list

  The indirect form of a builtin ``list``, constructed by a ``proxy_handler`` out of a mapping.
  Instances of this class behave like a regular list, with the following exceptions:

  - A proxy_list is only mutable (i.e: Its elements can be set) iff the underlying mapping is read-write,
    and if its elements are all primitives (integers or floats).
  - The size of a proxy_list cannot be modified, even if the list itself is mutable. That means that the
    following interfaces are not available: `append`, `clear`, `extend`, `insert`, `pop`, `remove`, `reverse`, `sort`
  - A proxy_list implements 2 methods not present in regular lists, specified below:

  .. py:method:: atomic_cas (self, index, expected, new)

    Atomically compares the value of the list at position *index*, and if it's equal to *expected*,
    sets it to *new*. This method only works when the proxy_list holds primitive elements.
    Returns *True* if the operation succeeded; *False* otherwise.

  .. py:method:: atomic_add (self, index, value)

    Atomically adds *value* to the element in the proxy_list at position *index*. This method
    only works when the proxy_list holds primitive elements. Returns the previous element at
    the specified position.

.. py:class:: proxy_str

    Indirect form of a builtin ``str``. Implements the same interface.

.. py:class:: proxy_set

    Indirect form of a builtin ``frozenset``. Implements the same interface.

.. py:class:: proxy_dict

    Indirect form of a builtin ``dict``. Instances of this class are always immutable, which
    means that the following interfaces are not available: `clear`, `pop`, `popitem`, `setdefault`,
    `update`. In addition, since a proxy_dict is only built from a proxy_handler, the class method
    `fromkeys` is not implemented.

Custom objects
--------------

When a user-defined class is packed and then unpacked, `zser` dynamically creates a proxy
class to masquerade it. Instances of this newly created class implements the same methods
and have the same properties of the original object, with the following caveats:

  - The object's slots are implemented as descriptors that access the data via a proxy_handler.
  - The object's slots can be mutated iff the the underlying mapping is mutable, and if
    their type is primitive (integer or float)
  - The descriptors that implement the object's slots have 2 additional methods: `cas` and
    `add` that can be used to *atomically* modify their values. They can be used as such:

  .. code-block:: python

    x = myclass (value = 1)   # Create object with slot named 'value'
    proxy = zser.unpack_from (zser.pack (x), rw = True)
    type(proxy).value.add (-1)   # Atomically adds -1 to proxy's value
    type(proxy).value.cas (0, 2)   # Atomic CAS on proxy's value

Module functions
----------------

.. py:function:: xhash (obj, seed = 0)

    Compute the hash code for object ``obj``, using ``seed`` as the starting value.
    The return value is stable across different processes, and is unaffected by
    environment variables and any other external parameters. Supported types are
    the following: `int`, `float`, `str`, `frozenset`, `tuple` and all proxies.

.. py:decorator:: register_pack (type)

    Registers a packing routine for the specified type. Once registered, if a ``packer``
    encounters an object of this type, the function will be called with the packer
    as its first argument, and the object as the second one.

.. py:decorator:: register_unpack (type)

    Same as above, only the callback is invoked when unpacking. Also, the callback
    for unpacking receives 3 arguments: The type of the object that should be unpacked,
    the ``proxy_handler``, and the offset at which the unpacking takes place.

.. py:function:: pack (obj, \**kwargs)

    Returns the binary representation of the object as a bytearray. Equivalent to
    creating a ``packer`` with the passed keyword arguments, calling ``pack`` with
    the passed object and then returning the value of calling ``as_bytearray``.

.. py:function:: pack_into (obj, place, offset = None, \**kwargs)

    Packs an object at a specific offset in the destination. The parameter ``place``
    can be a bytearray, in which case the object will be written at the specified
    offset (or concatenated, if *offset* is None). Otherwise, ``place`` must
    implement a method, ``write``, which will be called with the packed object,
    and ``seek``, if the offset is not None, in order to write the object at the
    specified offset (i.e: Like a file does).
    Returns the number of writes written.

.. py:function:: unpack_from (place, offset = 0, \**kwargs)

    Unpacks an object from the specified input and from an offset.
    The keyword arguments are used to construct a ``proxy_handler``. See its documentation
    for a description of its parameters.

.. py:function:: unpack_as (place, code, offset = 0, \**kwargs)

    Unpacks an object from the specified input, and with the specified typecode and offset.
    The typecode can be one of the following module constants:
        - TYPE_INT: Signed integer
        - TYPE_UINT: Unsigned integer
        - TYPE_FLOAT: Floating point value
        - TYPE_BIGINT: Arbitrary precision number
        - TYPE_NONE, TYPE_TRUE, TYPE_FALSE: The constants *None*, *True*, *False*
        - TYPE_BACKREF: A reference to an object that was previously serialized
        - TYPE_STR, TYPE_BYTES, TYPE_BYTEARRAY, TYPE_LIST, TYPE_TUPLE, TYPE_SET, TYPE_DICT: Self-explanatory
        - TYPE_OBJECT: Any object of a type not specified

.. py:function:: unproxy (obj)

    Converts a proxy object (proxy_list, proxy_str, proxy_set, proxy_dict) into its 'regular'
    counterpart, recursively.
