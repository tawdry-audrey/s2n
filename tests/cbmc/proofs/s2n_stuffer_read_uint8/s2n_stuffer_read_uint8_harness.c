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

#include "stuffer/s2n_stuffer.h"

#include <assert.h>

#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/make_common_datastructures.h>
#include <cbmc_proof/proof_allocators.h>

void s2n_calculate_stacktrace() {}

void s2n_stuffer_read_uint8_harness() {
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    uint8_t dest;
    __CPROVER_assume(s2n_stuffer_is_valid(stuffer));

    struct s2n_stuffer old_stuffer = *stuffer;

    /* Store a byte from the stuffer to compare if the copy fails */
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Store a byte from the stuffer to compare if the copy succeeds */
    struct store_byte_from_buffer copied_byte;
    if(s2n_stuffer_data_available(stuffer) >= sizeof(uint8_t)) {
        save_byte_from_array(&stuffer->blob.data[old_stuffer.read_cursor], sizeof(uint8_t), &copied_byte);
    }

    if (s2n_stuffer_read_uint8(stuffer, &dest) == S2N_SUCCESS) {
        assert(stuffer->read_cursor == old_stuffer.read_cursor + sizeof(uint8_t));
        assert(stuffer->blob.data[old_stuffer.read_cursor] == dest);
    } else {
	    assert(stuffer->read_cursor == old_stuffer.read_cursor);
    }

    assert_byte_from_blob_matches(&stuffer->blob, &old_byte_from_stuffer);
    assert(s2n_stuffer_is_valid(stuffer));
}
