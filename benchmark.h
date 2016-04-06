/*
 * af_ktls tool
 *
 * Copyright (C) 2016 Fridolin Pokorny <fpokorny@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <sys/time.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>

typedef void (*sighandler_t)(int);

struct benchmark_st
{
  struct timeval start;
  sighandler_t old_handler;
};

extern int benchmark_must_finish;

int start_benchmark(struct benchmark_st * st, time_t secs);
int stop_benchmark(struct benchmark_st * st, unsigned long * elapsed);

