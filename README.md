## About zser

This library aims to implement very fast (de)serialization of arbitrary objects.
Its main purpose is to provide O(1) unpacking, even when the input source is
big (even larger than the available memory), since many of the objects that can
be returned are mapped directly on top of the input source. Thus, *zser* can
be thought of as 'zero-copy serialization', hence its name.

With the exception of some complex-to-serialize types, *zser* supports every
python builtin, and also any user-defined class, although extension types (those
defined in C) are not supported out of the bat. Still, the library allows users
to extend the functionality to support any type. Consult the documentation for
further details.

### Basic example

Here's how 2 processes could share a chunk of data, and potentially modify it as
well, in an atomic way:

```python
    import zser

    data = { "abc": [1, 2, 3] }
    with open ("input", "wb") as f:
        zser.pack_into (data, f)

    # At this point any number of processes can map the file above
    with open ("input", "r+b") as f:
        data = zser.unpack_from (f, rw = True)   # Unpacked in O(1) time.

    lst = data["abc"]
    # The above returns a 'ProxyList' instead of a Python list
    # It consumes a fixed amount of memory, independent of the number
    # of elements. It implements mostly the same interface, with some
    # additions to make it easy to share and modify across processes:
    lst.atomic_cas (1, 2, -2)
    lst.atomic_add (1, 40)
    lst[1]   # 38
```

### Installation

Simply run:

```shell
    python3 setup.py install
```

And to run tests:

```shell
  python3 setup.py test
```

Or simply:

```shell
  pytest
```
