#ifndef _LOG_H
#define _LOG_H

#ifndef MAX_LOGLEVEL
#  define MAX_LOGLEVEL LOG_DEBUG
#endif
#ifndef DEFAULT_LOGLEVEL
#  define DEFAULT_LOGLEVEL LOG_NOTICE
#endif

#ifdef LOG_FUNCNAME
#define _func_fmt "%s: "
#define _func_arg __func__
#else
#define _func_fmt "%s"
#define _func_arg ""
#endif

extern int log_level;
extern bool log_timestamp;
#define _TIME_FMT "[%ld.%06ld] "
#define log(lvl, format, ...) \
	do {								\
		int __lvl = (lvl);					\
									\
		if (__lvl <= MAX_LOGLEVEL && __lvl <= log_level) {	\
			if (log_timestamp) {				\
				struct timespec __ts;			\
									\
				clock_gettime(CLOCK_MONOTONIC, &__ts);	\
				fprintf(stderr,				\
					_TIME_FMT _func_fmt format,	\
					__ts.tv_sec, __ts.tv_nsec / 1000,\
					_func_arg,			\
					##__VA_ARGS__);			\
			} else {					\
				fprintf(stderr, _func_fmt format,	\
					_func_arg,			\
					##__VA_ARGS__);			\
			};						\
		}							\
	} while (0)

#endif /* _LOG_H */
