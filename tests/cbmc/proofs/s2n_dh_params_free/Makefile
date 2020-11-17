# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

# Expected runtime is less than 5 seconds.

CBMCFLAGS +=

HARNESS_ENTRY = s2n_dh_params_free_harness
HARNESS_FILE = $(HARNESS_ENTRY).c

PROOF_SOURCES += $(HARNESS_FILE)
PROOF_SOURCES += $(PROOF_SOURCE)/make_common_datastructures.c
PROOF_SOURCES += $(PROOF_STUB)/s2n_is_in_fips_mode.c

PROJECT_SOURCES += $(SRCDIR)/crypto/s2n_dhe.c

# We abstract these functions because manual inspection demonstrates they are unreachable.

UNWINDSET +=

include ../Makefile.common
