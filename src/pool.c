/* Persistent worker pool (see pool.h).
 *
 * Joining a job and publishing one both happen under the mutex, and the
 * submitter waits for every worker of the previous job to leave before it
 * rewrites the job fields: a worker that wakes late can only ever join the
 * job that is current when it takes the lock, never read a half-written one.
 * A worker that claimed an item is counted in active until it has finished
 * it, so "the caller ran out of items and active is 0" means the job is done. */
#include "pool.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define MAX_WORKERS 63
/* An idle worker polls about as long as waking a parked one costs, then parks.
 * (A fixed count of sched_yield calls spun for milliseconds after every job.) */
#define SPIN_NS 30000

static void cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#endif
}

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

typedef struct pool {
    pthread_mutex_t mu;     /* guards active and job publication */
    pthread_cond_t wake, done;
    pthread_mutex_t submit; /* one job at a time */
    unsigned nworkers;
    unsigned active;        /* workers inside the current job (under mu) */
    atomic_ulong gen;       /* bumped for every job (read without mu while spinning) */
    imdb_task_fn fn;        /* the current job, written under mu before gen moves */
    void *ctx;
    size_t n;
    atomic_size_t next;     /* next item to claim */
} pool;

static pool g_pool;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static _Thread_local bool t_inside;

static void run_items(pool *p)
{
    t_inside = true;
    for (;;) {
        size_t i = atomic_fetch_add_explicit(&p->next, 1, memory_order_relaxed);
        if (i >= p->n) break;
        p->fn(p->ctx, i);
    }
    t_inside = false;
}

static void *worker(void *arg)
{
    pool *p = arg;
    pthread_mutex_lock(&p->mu);
    unsigned long seen = atomic_load(&p->gen);
    pthread_mutex_unlock(&p->mu);
    for (;;) {
        uint64_t t0 = mono_ns();
        for (unsigned k = 1; atomic_load_explicit(&p->gen, memory_order_relaxed) == seen; k++) {
            cpu_relax();
            if (k % 64 == 0 && mono_ns() - t0 > SPIN_NS) break;
        }
        pthread_mutex_lock(&p->mu);
        while (atomic_load(&p->gen) == seen) pthread_cond_wait(&p->wake, &p->mu);
        seen = atomic_load(&p->gen);
        p->active++;
        pthread_mutex_unlock(&p->mu);
        run_items(p);
        pthread_mutex_lock(&p->mu);
        if (--p->active == 0) pthread_cond_broadcast(&p->done);
        pthread_mutex_unlock(&p->mu);
    }
    return NULL;
}

/* fork() copies only the calling thread. Holding both locks across it means no
 * job is running (the submitter holds submit until its job is done), so the
 * child can drop its copy of the workers and run every par_for inline. Do not
 * fork from inside a pool item. */
static void fork_prepare(void)
{
    pthread_mutex_lock(&g_pool.submit);
    pthread_mutex_lock(&g_pool.mu);
}

static void fork_parent(void)
{
    pthread_mutex_unlock(&g_pool.mu);
    pthread_mutex_unlock(&g_pool.submit);
}

static void fork_child(void)
{
    g_pool.nworkers = 0;
    g_pool.active = 0;
    pthread_mutex_unlock(&g_pool.mu);
    pthread_mutex_unlock(&g_pool.submit);
}

static void pool_init(void)
{
    pool *p = &g_pool;
    pthread_mutex_init(&p->mu, NULL);
    pthread_mutex_init(&p->submit, NULL);
    pthread_cond_init(&p->wake, NULL);
    pthread_cond_init(&p->done, NULL);
    long cpus;
    cpu_set_t set;
    if (sched_getaffinity(0, sizeof set, &set) == 0) cpus = CPU_COUNT(&set);
    else cpus = sysconf(_SC_NPROCESSORS_ONLN);
    const char *env = getenv("IMDB_THREADS");
    if (env && *env) {
        char *end;
        long v = strtol(env, &end, 10);
        if (*end == 0 && v >= 1 && v <= MAX_WORKERS + 1) cpus = v;
    }
    if (cpus < 1) cpus = 1;
    unsigned want = (unsigned)(cpus - 1 > MAX_WORKERS ? MAX_WORKERS : cpus - 1);
    for (unsigned i = 0; i < want; i++) {
        pthread_t th;
        pthread_attr_t a;
        pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &a, worker, p) == 0) p->nworkers++;
        pthread_attr_destroy(&a);
    }
    if (p->nworkers) pthread_atfork(fork_prepare, fork_parent, fork_child);
}

unsigned imdb_pool_threads(void)
{
    pthread_once(&g_once, pool_init);
    return g_pool.nworkers + 1;
}

void imdb_par_for(size_t n, imdb_task_fn fn, void *ctx)
{
    if (n == 0) return;
    pthread_once(&g_once, pool_init);
    pool *p = &g_pool;
    if (t_inside || p->nworkers == 0 || n == 1) { /* nested, no workers, or nothing to share */
        for (size_t i = 0; i < n; i++) fn(ctx, i);
        return;
    }
    pthread_mutex_lock(&p->submit);
    pthread_mutex_lock(&p->mu);
    while (p->active) pthread_cond_wait(&p->done, &p->mu); /* stragglers of the previous job */
    p->fn = fn;
    p->ctx = ctx;
    p->n = n;
    atomic_store(&p->next, 0);
    atomic_fetch_add(&p->gen, 1);
    pthread_cond_broadcast(&p->wake);
    pthread_mutex_unlock(&p->mu);
    run_items(p);
    pthread_mutex_lock(&p->mu);
    while (p->active) pthread_cond_wait(&p->done, &p->mu);
    pthread_mutex_unlock(&p->mu);
    pthread_mutex_unlock(&p->submit);
}
