/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "api/s2n.h"
#include "utils/s2n_safety.h"

#include <sys/param.h>
#include <assert.h>

#include <cbmc_proof/proof_allocators.h>

void s2n_constant_time_pkcs1_unpad_or_dont_harness() {
    /* Non-deterministic inputs. */
    uint32_t len;
    uint32_t destlen;
    uint32_t srclen;
    uint8_t dont;
    __CPROVER_assume(len < MAX_ARR_LEN);
    __CPROVER_assume(destlen >= len);
    __CPROVER_assume(srclen >= len + 1 && srclen <= (MAX_ARR_LEN + 3));
    uint8_t * dest = can_fail_malloc(destlen);
    uint8_t * src = can_fail_malloc(srclen);
    uint8_t old_src_byte;
    uint8_t old_dest_byte;
    uint32_t index;
    __CPROVER_assume(index < len);

    /* Pre-conditions. */
    if (len != 0) {
        __CPROVER_assume(dest != NULL);
        __CPROVER_assume(src != NULL);
        old_src_byte = src[srclen - len + index];
        old_dest_byte = dest[index];
    }

    s2n_constant_time_pkcs1_unpad_or_dont(dest, src, srclen, len);

    if (len != 0) {
        bool has_zero = false;
        for (uint32_t i = 2; i < srclen - len - 1; i++) {
            if(src[i] == 0x00) {
                has_zero = true;
            }
        }

        if (srclen >= (len + 3) && src[0] == 0x00 && src[1] == 0x02 && src[srclen - len - 1] == 0x00 && has_zero == false) {
            assert(dest[index] == old_src_byte);
        } else {
            assert(dest[index] == old_dest_byte);
        }
        assert(src[srclen - len + index] == old_src_byte);
    }
}
