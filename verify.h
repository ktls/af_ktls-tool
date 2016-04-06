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

#ifndef VERIFY_H_
#define VERIFY_H_

#include <stdbool.h>

extern int verify_sendpage(int ksd, bool tls);
extern int verify_transmission(int ksd);
extern int verify_splice_read(int ksd);
extern int verify_handling(int ksd, bool tls);

#endif

