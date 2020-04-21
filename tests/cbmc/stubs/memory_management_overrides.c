/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stdlib.h>

/**
 * FUNCTION: munlock
 *
 * We assert that the memory is readable
 */

int munlock(const void *addr, size_t len) {
    int rval;

    assert(__CPROVER_r_ok(addr, len));

    return rval;
}

/**
 * FUNCTION: mlock
 *
 * We assert that the memory is readable
 */

int mlock(const void *addr, size_t len) {
    int rval;

    assert(__CPROVER_r_ok(addr, len));

    return rval;
}

/**
 * FUNCTION: madvise
 *
 * We assert that the memory is readable
 */

int madvise(void *addr, size_t len, int advice) {
    int rval;

    assert(__CPROVER_r_ok(addr, len));

    return rval;
}

