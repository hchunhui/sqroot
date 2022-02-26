#include "array.h"
#include <sys/mman.h>

template class Array<char, 4096>;

template<typename T, size_t n> pthread_once_t Array<T, n>::once = PTHREAD_ONCE_INIT;
template<typename T, size_t n> pthread_key_t Array<T, n>::key;
template<typename T, size_t n>__thread int Array<T, n>::top;

static size_t round(size_t n)
{
	return ((n + 7) / 8 * 8 * 100 + 4095) / 4096 * 4096;
}

template<typename T, size_t n>
void Array<T, n>::destroy(void *pool)
{
	if (pool) {
		int ret = munmap(pool, round(n));
		assert(ret == 0);
	}
}

template<typename T, size_t n>
T *Array<T, n>::get()
{
	pthread_once(&once, key_alloc);
	T *pool = (T *) pthread_getspecific(key);
	if (!pool) {
		void *p = mmap(NULL, round(n), PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		assert(p != MAP_FAILED);
		pthread_setspecific(key, p);
		pool = (T *) p;
	}
	return pool;
}

template<typename T, size_t n>
void Array<T, n>::key_alloc()
{
	pthread_key_create(&key, destroy);
}
