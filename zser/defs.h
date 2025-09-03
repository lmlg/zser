#include <float.h>
#include <limits.h>
#include <stdint.h>

#define FLOAT32_MIN   FLT_MIN
#define FLOAT32_MAX   FLT_MAX

#define FLOAT64_MIN   DBL_MIN
#define FLOAT64_MAX   DBL_MAX

#define WORD_MAX   SIZE_MAX

static unsigned int
STR_KIND (PyObject *obj)
{
  return (PyUnicode_IS_ASCII (obj) ? 3 : PyUnicode_KIND (obj));
}

static PyObject*
STR_NEW (unsigned int code, size_t len, const void *ptr)
{
  PyUnicodeObject *p = PyObject_New (PyUnicodeObject, &PyUnicode_Type);
  PyCompactUnicodeObject *c = &p->_base;
  PyASCIIObject *b = &c->_base;

  p->data.any = (void *)ptr;
  b->length = len;
  b->hash = -1;
  b->state.compact = 0;

#if PY_MINOR_VERSION <= 11
  b->state.ready = 1;
#endif

  b->state.interned = 0;   // SSTATE_NOT_INTERNED
  if (code == 3)
    {
      b->state.ascii = 1;
      b->state.kind = 1;
      c->utf8 = (char *)p->data.any;
      c->utf8_length = b->length;
    }
  else
    {
      b->state.ascii = 0;
      b->state.kind = code;

#if PY_MINOR_VERSION <= 11
      if (code == sizeof (wchar_t))
        {
          b->wstr = (wchar_t *)p->data.any;
          c->wstr_length = b->length;
        }
#endif
    }

  return ((PyObject *)p);
}

static void
STR_FINI (PyObject *obj)
{
  /* Modify the object so that all its internal pointers are NULL, thus
   * preventing any crashes caused by calling 'free' on mmap'd buffers. */
  PyUnicodeObject *p = (PyUnicodeObject *)obj;
  p->data.any = NULL;
  p->_base.utf8 = NULL;
#if PY_MINOR_VERSION <= 11
  p->_base._base.wstr = NULL;
#endif
}

static int
TYPE_PATCH (PyTypeObject *tp, binaryfunc add, binaryfunc mod, binaryfunc mul)
{
  if (!tp)
    return (-1);

  PyNumberMethods *num = tp->tp_as_number;
  if (!num)
    return (-1);

  num->nb_add = add;
  num->nb_remainder = mod;
  num->nb_multiply = mul;
  return (0);
}

/* Atomic definitions. */

#define atomic_fence()   __atomic_thread_fence (__ATOMIC_SEQ_CST)

#define atomic_is_lock_free(ptr, size)   \
  __atomic_is_lock_free ((size), (ptr))

#define atomic_cas_bool(ptr, exp, nval)   \
  __atomic_compare_exchange ((ptr), (exp), (nval), 1,   \
                             __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)

#define atomic_add(ptr, valp)   \
   *(valp) = __atomic_fetch_add ((ptr), *(valp), __ATOMIC_SEQ_CST)
