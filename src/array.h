#ifndef ARRAY_H
#define ARRAY_H

#include <stdint.h>
#include <assert.h>

template<typename T, size_t n>
class Array {
	static __thread T pool[1000][n];
	static __thread int top;
	T *data_;
public:
	T *data() { return data_; }
	T &operator[](size_t i) {
		return data_[i];
	}

	Array() {
		assert(top < 1000);
		data_ = pool[top++];
	}

	~Array() {
		top--;
	}
};

#endif /* ARRAY_H */
