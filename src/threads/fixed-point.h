#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

/* 17.14 fixed-point number representation */
#define FP_P 17
#define FP_Q 14

/* FP_F = 2 ^ 14 */
#define FP_F (1 << FP_Q)

/* Function macros to deal with fixed-point arithmetic */
#define conv_int_to_fixed(N)               (N * FP_F)

#define conv_fixed_to_int_round_to_zero(X) (X / FP_F)

#define conv_fixed_to_int_round_to_nearest(X)  \
                (X >= 0 ? ((X + (FP_F / 2)) / FP_F) : ((X - (FP_F / 2)) / FP_F))

#define add_fixed_to_fixed(X, Y)           (X + Y)

#define add_fixed_to_int(X, N)             (X + (N * FP_F))

#define sub_fixed_from_fixed(X, Y)         (X - Y)

#define sub_int_from_fixed(N, X)           (X - (N * FP_F))

#define mul_fixed_by_fixed(X, Y)           ((((int64_t) X) * Y) / FP_F)

#define mul_fixed_by_int(X, N)             (X * N)

#define div_fixed_by_fixed(X, Y)           ((((int64_t) X) * FP_F) / Y)

#define div_fixed_by_int(X, N)             (X / N)

#endif /* threads/fixed-point.h */
