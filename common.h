#ifndef _COMMON_H
#define _COMMON_H

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define min(x, y) ((x) > (y) ? (y) : (x))
#define max(x, y) ((x) > (y) ? (x) : (y))

#define __stringify_1(x...) #x
#define __stringify(x...)  __stringify_1(x)

#define CLEANUP_FUNC(type) \
static void __cleanup_ ## type ##_p(type ** __p) \
{						 \
	if (*__p) {				 \
		free(*__p);			 \
		*__p = NULL;			 \
	}					 \
}

#define CLEANUP(__t, __v) \
	__t *__v __attribute__((cleanup(__cleanup_ ## __t ## _p)))

#endif
