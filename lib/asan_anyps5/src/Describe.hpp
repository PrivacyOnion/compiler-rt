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

#include <cstddef>
#include <cstdint>
#include <string>

namespace AsanRuntime {

struct RegionInfo {
    const char* kind;
    std::uintptr_t begin;
    std::size_t size;
    std::string name;
};

RegionInfo LocateRegion_nid_no_patch(std::uintptr_t address);
std::string DescribeAddress_nid_no_patch(std::uintptr_t address, std::size_t accessSize);

}  // namespace AsanRuntime
