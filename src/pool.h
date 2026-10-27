/*
 * A persistent pool of worker threads for data-parallel loops (VERIFY, the
 * digest arithmetic, large commits). It replaces creating threads per call.
 *
 * Model: imdb_par_for(n, fn, ctx) runs fn(ctx, i) for every i in [0, n) on the
 * workers and the calling thread, and returns when all have finished. Items
 * are claimed one at a time from a shared counter, so uneven items balance
 * themselves. The pool is created on first use with one worker per online CPU
 * in the process's affinity mask minus the caller (IMDB_THREADS overrides; 1
 * means no workers). Workers spin briefly for the next job, then park.
 *
 * Results must not depend on which thread ran which item: callers combine
 * per-item outputs in item order, or with commutative exact arithmetic
 * (LtHash lanes, int128 sums), so any thread count gives identical bytes.
 * A par_for called from inside an item runs inline (no nesting deadlock).
 */
#ifndef IMDB_POOL_H
#define IMDB_POOL_H

#include <stddef.h>

typedef void (*imdb_task_fn)(void *ctx, size_t i);

void imdb_par_for(size_t n, imdb_task_fn fn, void *ctx);
/* Threads that run items: the workers plus the caller (>= 1). */
unsigned imdb_pool_threads(void);

#endif
