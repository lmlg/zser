#include <stdint.h>

#define IWORD_MAX   INTPTR_MAX
#define IWORD_MIN   INTPTR_MIN
#define WORD_MAX    UINTPTR_MAX

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
  b->state.ready = 1;
  b->state.interned = 0;
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
      if (code == sizeof (wchar_t))
        {
          b->wstr = (wchar_t *)p->data.any;
          c->wstr_length = b->length;
        }
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
  p->_base._base.wstr = NULL;
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

#ifdef __GNUC__

static void
atomic_fence (void)
{
  __atomic_thread_fence (__ATOMIC_SEQ_CST);
}

static int
atomic_cas_i (void *ptr, Py_ssize_t exp, Py_ssize_t nval)
{
  return (__atomic_compare_exchange_n ((Py_ssize_t *)ptr, &exp, nval,
    0, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
}

static Py_ssize_t
atomic_add_i (void *ptr, Py_ssize_t val)
{
  return (__atomic_fetch_add ((Py_ssize_t *)ptr, val, __ATOMIC_SEQ_CST));
}

static int
atomic_cas_I (void *ptr, size_t exp, size_t nval)
{
  return (__atomic_compare_exchange_n ((size_t *)ptr, &exp, nval,
    1, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
}

static size_t
atomic_add_I (void *ptr, size_t val)
{
  return (__atomic_fetch_add ((size_t *)ptr, val, __ATOMIC_SEQ_CST));
}

static int
_atomic_cas_f (void *ptr, double exp, double nval)
{
  uint64_t q_exp = 0, q_nval = 0;

  if (sizeof (double) > sizeof (q_exp) ||
      !__atomic_always_lock_free (sizeof (q_exp), &q_exp))
    return (-1);

  memcpy (&q_exp, &exp, sizeof (exp));
  memcpy (&q_nval, &nval, sizeof (nval));

  return (__atomic_compare_exchange_n ((uint64_t *)ptr, &q_exp, q_nval,
    1, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
}

#elif defined (_MSC_VER)

#include <intrin.h>
#include <winnt.h>

static void
atomic_fence (void)
{
  _ReadWriteBarrier ();
  MemoryBarrier ();
}

static Py_ssize_t
atomic_cas_i (void *ptr, Py_ssize_t exp, Py_ssize_t nval)
{
  return (InterlockedCompareExchange64 ((LONG64 volatile *)ptr,
                                        (LONG64)exp, (LONG64)nval));
}

static Py_ssize_t
atomic_add_i (void *ptr, Py_ssize_t val)
{
  return (InterlockedExchangeAdd64 ((LONG64 volatile *)ptr, val));
}

static size_t
atomic_cas_I (void *ptr, size_t exp, size_t nval)
{
  return (InterlockedCompareExchange64 ((LONG64 volatile *)ptr,
                                        (LONG64)exp, (LONG64)nval));
}

static size_t
atomic_add_I (void *ptr, size_t val)
{
  return (InterlockedExchangeAdd64 ((LONG64 volatile *)ptr, val));
}

static int
_atomic_cas_f (void *ptr, double exp, double nval)
{
  uint64_t q_exp = 0, q_nval = 0;

  memcpy (&q_exp, &exp, sizeof (exp));
  memcpy (&q_nval, &nval, sizeof (nval));
  return (InterlockedCompareExchange ((LONG64 volatile *)ptr,
                                      q_exp, q_nval) == q_exp);
}

#else

#  error "Unsupported platform. Please (re)port"

#endif

