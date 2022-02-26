#include "array.h"
#include <sys/mman.h>

template class Array<char, 4096>;

template<typename T, size_t n> std::atomic<int> Array<T, n>::once;
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
	int val = once.load(std::memory_order_acquire);
	if (val != 2) {
		val = once.load(std::memory_order_acquire);
		while (val != 2 && !once.compare_exchange_weak(val, 1, std::memory_order_acq_rel));
		if (val == 0) {
			key_alloc();
			once.store(2, std::memory_order_release);
		} else if (val == 1) {
			while (once.load(std::memory_order_acquire) != 2);
		}
	}
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
