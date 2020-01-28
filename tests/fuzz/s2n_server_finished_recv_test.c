/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"
#include "s2n_test.h"

static const uint8_t TLS_VERSIONS[] = {S2N_TLS12, S2N_SSLv3};

static void s2n_fuzz_atexit()
{
    s2n_cleanup();
}

int LLVMFuzzerInitialize(const uint8_t *buf, size_t len)
{
#ifdef S2N_TEST_IN_FIPS_MODE
    S2N_TEST_ENTER_FIPS_MODE();
#endif

    GUARD(s2n_init());
    GUARD_STRICT(atexit(s2n_fuzz_atexit));
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    for(int version = 0; version < s2n_array_len(TLS_VERSIONS); version++){
        /* Setup */
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        notnull_check(client_conn);
        GUARD(s2n_stuffer_write_bytes(&client_conn->handshake.io, buf, len));
        client_conn->actual_protocol_version = TLS_VERSIONS[version];

        /* Test value chosen at random as it is only needed for comparison with handshake.io */
        client_conn->handshake.server_finished[0] = 1;

        /* Run Test
         * Do not use GUARD macro here since the connection memory hasn't been freed.
         */
        s2n_server_finished_recv(client_conn);

        /* Cleanup */
        GUARD(s2n_connection_free(client_conn));
    }

    return 0;
}
