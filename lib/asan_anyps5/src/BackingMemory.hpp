// AnyPS5 sanitizer runtime host integration, introduced 2026-10-30.
// SPDX-License-Identifier: GPL-2.0-only
// See LICENSE.GPL-2.0 and NOTICE in lib/asan_anyps5.

#pragma once

#include <cstddef>

namespace AsanRuntime {

extern "C" void* AllocateBacking_nid_no_patch(std::size_t size, std::size_t alignment) noexcept;
extern "C" void FreeBacking_nid_no_patch(void* pointer, std::size_t alignment) noexcept;

}
