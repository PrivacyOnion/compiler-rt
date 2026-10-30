// AnyPS5 sanitizer runtime host integration, introduced 2026-10-30.
// SPDX-License-Identifier: GPL-2.0-only
// See LICENSE.GPL-2.0 and NOTICE in lib/asan_anyps5.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace AsanRuntime::StackTrace {

std::string RenderFrame_nid_no_patch(const char* format, unsigned frameNumber, std::uintptr_t address);
std::string Print_nid_no_patch(const std::uintptr_t* returnAddresses, std::size_t count);
void Symbolize_nid_no_patch(std::uintptr_t pc, const char* format, char* output, std::size_t outputSize);

}  // namespace AsanRuntime::StackTrace
