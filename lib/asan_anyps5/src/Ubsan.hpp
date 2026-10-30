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

namespace AsanRuntime::Ubsan {

using ValueHandle = std::uintptr_t;

enum class Check {
    TypeMismatch,
    LegacyTypeMismatch,
    AlignmentAssumption,
    AddOverflow,
    SubOverflow,
    MulOverflow,
    NegateOverflow,
    DivremOverflow,
    ShiftOutOfBounds,
    OutOfBounds,
    BuiltinUnreachable,
    MissingReturn,
    VlaBound,
    FloatCastOverflow,
    LoadInvalidValue,
    ImplicitConversion,
    InvalidBuiltin,
    NonNullReturn,
    LegacyNonNullReturn,
    NullabilityReturn,
    NonNullArg,
    NullabilityArg,
    PointerOverflow,
    FunctionTypeMismatch,
};

void Handle_nid_no_patch(Check check, void* data, ValueHandle first, ValueHandle second, ValueHandle third, bool unrecoverable, std::uintptr_t pc, std::uintptr_t bp);

void GetCurrentReportData_nid_no_patch(const char** issueKind, const char** message, const char** filename, unsigned* line, unsigned* column, char** memoryAddress);

}  // namespace AsanRuntime::Ubsan
