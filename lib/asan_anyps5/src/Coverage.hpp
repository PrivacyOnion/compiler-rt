// AnyPS5 sanitizer runtime port, modified 2026-10-30.
// SPDX-License-Identifier: GPL-2.0-only AND Apache-2.0 WITH LLVM-exception
//
// Compiler-rt portions:
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
//
// AnyPS5 changes remain under GPLv2. See LICENSE.GPL-2.0 and NOTICE in
// lib/asan_anyps5, and LICENSE.TXT at the repository root.

#pragma once

#include <cstdint>

namespace AsanRuntime::Coverage {

void InitTracePcGuard_nid_no_patch(std::uint32_t* start, std::uint32_t* end);
void TracePcGuard_nid_no_patch(std::uint32_t* guard, std::uintptr_t pc);
void DumpTracePcGuard_nid_no_patch();
void DumpCoverage_nid_no_patch(const std::uintptr_t* pcs, std::uintptr_t length);

}  // namespace AsanRuntime::Coverage
