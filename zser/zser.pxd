from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release
from cpython.bytearray cimport PyByteArray_Resize
from cpython.object cimport PyTypeObject, binaryfunc
from cpython.slice cimport PySlice_GetIndices
from libc.math cimport modf, isnan, isinf
from libc.string cimport memcpy, memcmp

cdef extern from "defs.h":
  cdef const Py_ssize_t IWORD_MIN
  cdef const Py_ssize_t IWORD_MAX
  cdef const size_t WORD_MAX

  # These are actually provided by CPython, but aren't exported in
  # some cython versions, so we declare them here.
  cdef void* PyUnicode_DATA (object)
  cdef object _PyUnicode_Copy (object)
  cdef str PyUnicode_FromStringAndSize (const char *, Py_ssize_t)
  cdef object PyUnicode_AsEncodedString (object, char *, char *)

  cdef unsigned int STR_KIND (object)
  cdef object STR_NEW (unsigned int, size_t, const void *)
  cdef void STR_FINI (object)

  cdef int TYPE_PATCH (PyTypeObject *, binaryfunc,
                       binaryfunc, binaryfunc) except -1

  cdef void atomic_fence ()
  cdef int atomic_cas_i (void *, Py_ssize_t, Py_ssize_t)
  cdef Py_ssize_t atomic_add_i (void *, Py_ssize_t)
  cdef int atomic_cas_I (void *, size_t, size_t)
  cdef size_t atomic_add_I (void *, size_t)
  cdef int _atomic_cas_f (void *, double, double)

ctypedef enum tpcode:
  INT,
  UINT,
  FLOAT,
  NUM,
  STR,
  BYTES,
  BYTEARRAY,
  LIST,
  TUPLE,
  NONE,
  TRUE,
  FALSE,
  SET,
  DICT,
  BACKREF,
  OTHER,
  CUSTOM

ctypedef enum direction:
  PACK
  UNPACK

ctypedef object (*dict_iter_fn) (const void *, size_t, object)
