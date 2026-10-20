# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Sets ANDROID without setting CMAKE_SYSTEM_NAME. A toolchain file is
# read during project(), so this flag is invisible to the refusal that
# runs before project() and visible to the one that runs after it.
# CMAKE_SYSTEM_NAME stays the host's, which keeps project() out of
# Platform/Android and its NDK search. tests/cmake-gate-test/run.sh
# asserts the second call is what refuses this file.

set(ANDROID TRUE)
