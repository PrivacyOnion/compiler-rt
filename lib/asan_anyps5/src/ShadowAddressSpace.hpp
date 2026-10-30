// AnyPS5 sanitizer runtime host integration, introduced 2026-10-30.
// SPDX-License-Identifier: GPL-2.0-only
// See LICENSE.GPL-2.0 and NOTICE in lib/asan_anyps5.

#pragma once

#include <cstddef>
#include <cstdint>

namespace AsanRuntime {

inline constexpr std::uintptr_t ShadowBase = 1ull << 40;
inline constexpr std::size_t ShadowSize = 1ull << 44;
extern "C" bool InitializeShadow_nid_no_patch() noexcept;
extern "C" bool ShadowRangeAvailable_nid_no_patch(std::uintptr_t begin, std::uintptr_t end) noexcept;

}
