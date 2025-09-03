from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release
from cpython.bytearray cimport PyByteArray_Resize
from cpython.object cimport PyTypeObject, binaryfunc
from cpython.slice cimport PySlice_GetIndices
from libc.math cimport modf, isnan, isinf
from libc.string cimport memcpy, memcmp

cdef extern from "defs.h":
  cdef const Py_ssize_t INT8_MIN
  cdef const Py_ssize_t INT8_MAX
  cdef const Py_ssize_t INT16_MIN
  cdef const Py_ssize_t INT16_MAX
  cdef const Py_ssize_t INT32_MIN
  cdef const Py_ssize_t INT32_MAX
  cdef const long long INT64_MIN
  cdef const long long INT64_MAX
  cdef const size_t WORD_MAX
  cdef const float FLOAT32_MIN
  cdef const float FLOAT32_MAX
  cdef const double FLOAT64_MIN
  cdef const double FLOAT64_MAX

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
  cdef bint atomic_is_lock_free (void *, size_t)
  cdef bint atomic_cas_bool (void *, void *, void *)
  cdef void atomic_add (void *, void *)

ctypedef enum tpcode:
  INT8,
  INT16,
  INT32,
  INT64,
  FLOAT32,
  FLOAT64,
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
