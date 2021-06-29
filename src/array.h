#ifndef ARRAY_H
#define ARRAY_H

#include <pthread.h>
#include <stdint.h>
#include <assert.h>

template<typename T, size_t n>
class Array {
	static pthread_once_t once;
	static pthread_key_t key;
	static __thread int top;
	T *data_;

	static void destroy(void *);
	static void key_alloc();
	static T *get();
public:
	T *data() { return data_; }
	T &operator[](size_t i) {
		return data_[i];
	}

	Array() {
		T *pool = get();
		assert(top < 100);
		data_ = pool + (n + 7) / 8 * 8 * top;
		top++;
	}

	~Array() {
		top--;
	}
};

#endif /* ARRAY_H */
