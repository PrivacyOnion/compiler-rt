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

namespace AsanRuntime::FakeStack {

void* Malloc_nid_no_patch(std::size_t classId, std::size_t size, bool always, std::uintptr_t realStack);
void Free_nid_no_patch(std::uintptr_t pointer, std::size_t classId, std::size_t size);
void* Current_nid_no_patch();
void* AddrIsIn_nid_no_patch(void* fakeStack, void* address, void** begin, void** end);
void HandleNoReturn_nid_no_patch();
void StartSwitchFiber_nid_no_patch(void** save, const void* bottom, std::size_t size);
void FinishSwitchFiber_nid_no_patch(void* save, const void** bottomOld, std::size_t* sizeOld);

}  // namespace AsanRuntime::FakeStack
