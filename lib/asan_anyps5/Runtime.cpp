// AnyPS5 sanitizer runtime port, modified 2026-10-30.
// SPDX-License-Identifier: GPL-2.0-only AND Apache-2.0 WITH LLVM-exception
//
// Compiler-rt portions:
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
//
// AnyPS5 changes remain under GPLv2. See LICENSE.GPL-2.0 and NOTICE in
// lib/asan_anyps5, and LICENSE.TXT at the repository root.

#include "asan_anyps5/Interface.hpp"
#include "asan_anyps5/src/ShadowAddressSpace.hpp"
#include "asan_anyps5/src/ShadowCheck.hpp"
#include "asan_anyps5/src/ErrorReport.hpp"
#include "asan_anyps5/src/Report.hpp"
#include "asan_anyps5/src/Allocator.hpp"
#include "asan_anyps5/src/Container.hpp"
#include "asan_anyps5/src/Coverage.hpp"
#include "asan_anyps5/src/ModuleLookup.hpp"
#include "asan_anyps5/src/ReportFile.hpp"
#include "asan_anyps5/src/StackTrace.hpp"
#include "asan_anyps5/src/Describe.hpp"
#include "asan_anyps5/src/FakeStack.hpp"
#include "asan_anyps5/src/Globals.hpp"
#include "asan_anyps5/src/Ubsan.hpp"
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <cstddef>
#include "SceTypes.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/General.hpp"

using AsanRuntime::Impl::__asan_region_is_poisoned_nid_no_patch;

static void RequireShadow_nid_no_patch(std::uintptr_t address, std::uintptr_t size, const char* function) {
    const auto begin = AsanRuntime::ShadowBase + (address >> 3);
    const auto end = size == 0 ? begin : AsanRuntime::ShadowBase + ((address + size - 1) >> 3) + 1;
    if (!AsanRuntime::ShadowRangeAvailable_nid_no_patch(begin, std::min(end, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) {
        ShadowUnavailable_nid_no_patch(function);
    }
}

static void UpdateIntraObjectShadow_nid_no_patch(std::uintptr_t address, std::uintptr_t size, bool poison, const char* function) {
    const auto end = address + size;
    if (size == 0 || size > 4096 || end < address || (end & 7) != 0 || end > (1ull << 47) ||
        (address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && end > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(function);
    }
    RequireShadow_nid_no_patch(address, size, function);
    auto* shadow = reinterpret_cast<std::uint8_t*>(AsanRuntime::ShadowBase + (address >> 3));
    auto* shadowEnd = reinterpret_cast<std::uint8_t*>(AsanRuntime::ShadowBase + (end >> 3));
    if ((address & 7) != 0) {
        *shadow++ = poison ? static_cast<std::uint8_t>(address & 7) : 0;
    }
    while (shadow != shadowEnd) {
        *shadow++ = poison ? 0xbb : 0;
    }
}

constexpr bool kPoisonArrayCookie = true;
constexpr std::uint8_t kAsanArrayCookieMagic = 0xac;
constexpr std::uint8_t kAsanHeapFreeMagic = 0xfd;

constexpr std::uintptr_t kAllocaRedzoneSize = 32;
constexpr std::uintptr_t kAllocaRedzoneMask = 31;
constexpr bool kPoisonPartial = true;
constexpr std::uint8_t kAsanAllocaLeftMagic = 0xca;
constexpr std::uint8_t kAsanAllocaRightMagic = 0xcb;

static void FastPoisonShadow_nid_no_patch(std::uintptr_t address, std::uintptr_t size, std::uint8_t value) {
    std::memset(reinterpret_cast<void*>(AsanRuntime::ShadowBase + (address >> 3)), value, size >> 3);
}

static void FastPoisonShadowPartialRightRedzone_nid_no_patch(std::uintptr_t address, std::uintptr_t sz, std::uintptr_t redzoneSize, std::uint8_t value) {
    auto* shadow = reinterpret_cast<std::int8_t*>(AsanRuntime::ShadowBase + (address >> 3));
    for (std::uintptr_t i = 0; i < redzoneSize; i += 8, ++shadow) {
        if (i + 8 <= sz) {
            *shadow = 0;
        } else if (i >= sz) {
            *shadow = static_cast<std::int8_t>(value);
        } else {
            *shadow = static_cast<std::int8_t>(kPoisonPartial ? (sz - i) : 0);
        }
    }
}

constexpr bool kAllowUserPoisoning = true;
constexpr std::int8_t kAsanUserPoisonedMemoryMagic = static_cast<std::int8_t>(0xf7);

namespace {

struct ShadowSegmentEndpoint {
    std::int8_t* chunk;
    std::int8_t offset;
    std::int8_t value;

    explicit ShadowSegmentEndpoint(std::uintptr_t a)
        : chunk(reinterpret_cast<std::int8_t*>(AsanRuntime::ShadowBase + (a >> 3))),
          offset(static_cast<std::int8_t>(a & 7)),
          value(chunk < reinterpret_cast<std::int8_t*>(AsanRuntime::ShadowBase + AsanRuntime::ShadowSize) ? *chunk : 0) {}
};

}  // namespace

namespace AsanRuntime {

extern "C" ErrorReport* CurrentErrorReport_nid_no_patch() noexcept {
    static ErrorReport report{};
    return &report;
}

static std::atomic<ErrorReportCallback> errorReportCallback{nullptr};

extern "C" ErrorReportCallback LoadErrorReportCallback_nid_no_patch() noexcept {
    return errorReportCallback.load(std::memory_order_acquire);
}

}  // namespace AsanRuntime

constexpr int kExitCode = 1;

static std::mutex reportMutex;
static thread_local bool reportInProgress = false;
static std::atomic<void (APS5_VABI*)()> deathCallback{nullptr};

namespace AsanRuntime {

extern "C" [[noreturn]] void Die_nid_no_patch() {
    if (const auto callback = deathCallback.load(std::memory_order_acquire)) {
        callback();
    }
    _Exit_nid_postfix(kExitCode);
}

void EmitDiagnostic_nid_no_patch(const std::string& text) {
    std::lock_guard lock(reportMutex);
    ReportFile::Write_nid_no_patch(text);
}

[[noreturn]] void ReportFatal_nid_no_patch(const ErrorReport& state, const std::string& text) {
    if (reportInProgress) {
        Die_nid_no_patch();
    }
    reportInProgress = true;
    std::unique_lock lock(reportMutex);
    *CurrentErrorReport_nid_no_patch() = state;
    ReportFile::Write_nid_no_patch(text);
    if (const auto callback = LoadErrorReportCallback_nid_no_patch()) {
        callback(text.c_str());
    }
    ReportFile::Write_nid_no_patch("ABORTING\n");
    Die_nid_no_patch();
}

}  // namespace AsanRuntime

using AsanRuntime::Die_nid_no_patch;

[[noreturn]] static void ReportGenericError_nid_no_patch(std::uintptr_t pc, std::uintptr_t bp, std::uintptr_t sp, std::uintptr_t address, bool isWrite, std::uintptr_t accessSize) {
    const bool inMemory = address < (1ULL << 47) &&
        !(address >= AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize) &&
        AsanRuntime::ShadowRangeAvailable_nid_no_patch(AsanRuntime::ShadowBase + (address >> 3), std::min(AsanRuntime::ShadowBase + (address >> 3) + 3, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize));
    const char* bug = "unknown-crash";
    std::uint8_t shadowValue = 0;
    if (inMemory) {
        bug = AsanRuntime::DescribeBug_nid_no_patch(reinterpret_cast<const std::uint8_t*>(AsanRuntime::ShadowBase + (address >> 3)), accessSize, shadowValue);
    }
    std::string text;
    AsanRuntime::AppendReportHeader_nid_no_patch(text, bug, address, pc, bp, sp, isWrite, accessSize);
    const auto dumpCenter = (AsanRuntime::ShadowBase + (address >> 3)) & ~static_cast<std::uintptr_t>(15);
    if (inMemory && AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(dumpCenter - 80, AsanRuntime::ShadowBase), std::min(dumpCenter + 96, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) {
        AsanRuntime::AppendShadowMemory_nid_no_patch(text, AsanRuntime::ShadowBase, AsanRuntime::ShadowSize, address);
    }
    AsanRuntime::ReportFatal_nid_no_patch({true, pc, bp, sp, address, isWrite, accessSize, bug, false}, text);
}

static void RequireGuestRange_nid_no_patch(std::uintptr_t address, std::uintptr_t size, const char* function) {
    const auto end = address + size;
    if (end < address || end > (1ULL << 47) ||
        (address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && end > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(function);
    }
    RequireShadow_nid_no_patch(address, size, function);
}

static void CheckRegion_nid_no_patch(std::uintptr_t address, std::uintptr_t size, bool isWrite, std::uintptr_t pc, std::uintptr_t bp) {
    if (const auto bad = __asan_region_is_poisoned_nid_no_patch(address, size); bad != 0) {
        std::uintptr_t local = 0;
        ReportGenericError_nid_no_patch(pc, bp, reinterpret_cast<std::uintptr_t>(&local), bad, isWrite, size);
    }
}

[[noreturn]] static void ReportSizeOverflow_nid_no_patch(std::uintptr_t offset, std::uintptr_t size) {
    std::string text = AsanRuntime::ReportSeparator_nid_no_patch();
    text += "ERROR: AddressSanitizer: negative-size-param: (size=";
    text += std::to_string(static_cast<std::intptr_t>(size));
    text += ")\n";
    AsanRuntime::ReportFatal_nid_no_patch({false, 0, 0, 0, offset, false, size, "negative-size-param", true}, text);
}

[[noreturn]] static void ReportRangesOverlap_nid_no_patch(const char* function, std::uintptr_t address1, std::uintptr_t length1, std::uintptr_t address2, std::uintptr_t length2) {
    std::string bug = function;
    bug += "-param-overlap";
    std::string text = AsanRuntime::ReportSeparator_nid_no_patch();
    text += "ERROR: AddressSanitizer: " + bug + ": memory ranges [";
    AsanRuntime::AppendPointer_nid_no_patch(text, address1);
    text += ",";
    AsanRuntime::AppendPointer_nid_no_patch(text, address1 + length1);
    text += ") and [";
    AsanRuntime::AppendPointer_nid_no_patch(text, address2);
    text += ", ";
    AsanRuntime::AppendPointer_nid_no_patch(text, address2 + length2);
    text += ") overlap\n";
    static thread_local std::string description;
    description = bug;
    AsanRuntime::ReportFatal_nid_no_patch({false, 0, 0, 0, address1, false, 0, description.c_str(), true}, text);
}

static void AccessRange_nid_no_patch(std::uintptr_t address, std::uintptr_t size, bool isWrite, std::uintptr_t pc, std::uintptr_t bp) {
    if (address > address + size) {
        ReportSizeOverflow_nid_no_patch(address, size);
    }
    if (size == 0) {
        return;
    }
    RequireGuestRange_nid_no_patch(address, size, "AccessRange");
    CheckRegion_nid_no_patch(address, size, isWrite, pc, bp);
}

static bool RangesOverlap_nid_no_patch(std::uintptr_t address1, std::uintptr_t length1, std::uintptr_t address2, std::uintptr_t length2) {
    return !(address1 + length1 <= address2 || address2 + length2 <= address1);
}

[[noreturn]] static void ReportBadContainerParams_nid_no_patch(std::uintptr_t beg, std::uintptr_t end, std::uintptr_t oldMid, std::uintptr_t newMid) {
    std::string text = AsanRuntime::ReportSeparator_nid_no_patch();
    text += "ERROR: AddressSanitizer: bad parameters to __sanitizer_annotate_contiguous_container:\n      beg     : ";
    AsanRuntime::AppendPointer_nid_no_patch(text, beg);
    text += "\n      end     : ";
    AsanRuntime::AppendPointer_nid_no_patch(text, end);
    text += "\n      old_mid : ";
    AsanRuntime::AppendPointer_nid_no_patch(text, oldMid);
    text += "\n      new_mid : ";
    AsanRuntime::AppendPointer_nid_no_patch(text, newMid);
    text += "\n";
    if (!AsanRuntime::Aligned_nid_no_patch(beg)) {
        text += "ERROR: beg is not aligned by 8\n";
    }
    AsanRuntime::ReportFatal_nid_no_patch({false, 0, 0, 0, 0, false, 0, "bad-__sanitizer_annotate_contiguous_container", true}, text);
}

[[noreturn]] static void ReportBadDoubleEndedParams_nid_no_patch(std::uintptr_t storageBeg, std::uintptr_t storageEnd, std::uintptr_t oldBeg, std::uintptr_t oldEnd, std::uintptr_t newBeg, std::uintptr_t newEnd) {
    std::string text = AsanRuntime::ReportSeparator_nid_no_patch();
    text += "ERROR: AddressSanitizer: bad parameters to __sanitizer_annotate_double_ended_contiguous_container:\n      storage_beg        : ";
    AsanRuntime::AppendPointer_nid_no_patch(text, storageBeg);
    text += "\n      storage_end        : ";
    AsanRuntime::AppendPointer_nid_no_patch(text, storageEnd);
    text += "\n      old_container_beg  : ";
    AsanRuntime::AppendPointer_nid_no_patch(text, oldBeg);
    text += "\n      old_container_end  : ";
    AsanRuntime::AppendPointer_nid_no_patch(text, oldEnd);
    text += "\n      new_container_beg  : ";
    AsanRuntime::AppendPointer_nid_no_patch(text, newBeg);
    text += "\n      new_container_end  : ";
    AsanRuntime::AppendPointer_nid_no_patch(text, newEnd);
    text += "\n";
    if (!AsanRuntime::Aligned_nid_no_patch(storageBeg)) {
        text += "ERROR: storage_beg is not aligned by 8\n";
    }
    AsanRuntime::ReportFatal_nid_no_patch({false, 0, 0, 0, 0, false, 0, "bad-__sanitizer_annotate_double_ended_contiguous_container", true}, text);
}

static bool AddressIsPoisoned_nid_no_patch(std::uintptr_t address) {
    const auto value = *reinterpret_cast<const std::int8_t*>(AsanRuntime::ShadowBase + (address >> 3));
    return value != 0 && static_cast<std::int8_t>(address & 7) >= value;
}

static void CheckAccess_nid_no_patch(std::uintptr_t address, std::uintptr_t size, bool isWrite, std::uintptr_t pc, std::uintptr_t bp, const char* function) {
    if (address + size < address || address + size > (1ULL << 47) ||
        (address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && address + size > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(function);
    }
    RequireShadow_nid_no_patch(address, size, function);
    const auto* shadow = reinterpret_cast<const std::uint8_t*>(AsanRuntime::ShadowBase + (address >> 3));
    std::uintptr_t value = shadow[0];
    if (size > 8) {
        std::uint16_t pair;
        std::memcpy(&pair, shadow, sizeof(pair));
        value = pair;
    }
    if (value == 0) {
        if (size > 8 && (address & 7) != 0 && AddressIsPoisoned_nid_no_patch(address + size - 1)) {
            CheckRegion_nid_no_patch(address, size, isWrite, pc, bp);
        }
        return;
    }
    if (size >= 8 || static_cast<std::int8_t>((address & 7) + size - 1) >= static_cast<std::int8_t>(value)) {
        std::uintptr_t local = 0;
        ReportGenericError_nid_no_patch(pc, bp, reinterpret_cast<std::uintptr_t>(&local), address, isWrite, size);
    }
}

static void CheckSmallRegion_nid_no_patch(std::uintptr_t address, std::uintptr_t size, bool isWrite, std::uintptr_t pc, std::uintptr_t bp) {
    if (__asan_region_is_poisoned_nid_no_patch(address, size) == 0) {
        return;
    }
    if (AddressIsPoisoned_nid_no_patch(address) || AddressIsPoisoned_nid_no_patch(address + size - 1)) {
        std::uintptr_t local = 0;
        ReportGenericError_nid_no_patch(pc, bp, reinterpret_cast<std::uintptr_t>(&local), __asan_region_is_poisoned_nid_no_patch(address, size), isWrite, size);
    }
}

namespace AsanRuntime::Impl {

void* __asan_addr_is_in_fake_stack_nid_no_patch(void* fakeStack, void* address, void** begin, void** end, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::FakeStack::AddrIsIn_nid_no_patch(fakeStack, address, begin, end);
}

int __asan_address_is_poisoned_nid_no_patch(const volatile void* address, [[maybe_unused]] const CallSite& callSite) {
    const auto value = reinterpret_cast<std::uintptr_t>(address);
    if (value >= (1ull << 47) ||
        (value >= AsanRuntime::ShadowBase && value < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize)) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireShadow_nid_no_patch(value, 1, callSite.function);
    return FindFirstPoisoned_nid_no_patch(reinterpret_cast<const std::int8_t*>(AsanRuntime::ShadowBase), AsanRuntime::ShadowSize, value, 1).has_value() ? 1 : 0;
}

void* __asan_aligned_alloc_nid_no_patch(std::size_t alignment, std::size_t size, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::AlignedAlloc_nid_no_patch(alignment, size, callSite.pc);
}

void __asan_alloca_poison_nid_no_patch(std::uintptr_t addr, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if ((addr & kAllocaRedzoneMask) != 0 || addr < kAllocaRedzoneSize) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    std::uintptr_t leftRedzoneAddr = addr - kAllocaRedzoneSize;
    std::uintptr_t partialRzAddr = addr + size;
    if (partialRzAddr < addr || partialRzAddr + kAllocaRedzoneMask < partialRzAddr) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    std::uintptr_t rightRzAddr = (partialRzAddr + kAllocaRedzoneMask) & ~kAllocaRedzoneMask;
    if (rightRzAddr + kAllocaRedzoneSize < rightRzAddr) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    std::uintptr_t rightRedzoneEnd = rightRzAddr + kAllocaRedzoneSize;
    if (rightRedzoneEnd < leftRedzoneAddr || rightRedzoneEnd > (1ULL << 47) ||
        (leftRedzoneAddr < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && rightRedzoneEnd > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireShadow_nid_no_patch(leftRedzoneAddr, rightRedzoneEnd - leftRedzoneAddr, callSite.function);
    std::uintptr_t partialRzAligned = partialRzAddr & ~static_cast<std::uintptr_t>(7);
    FastPoisonShadow_nid_no_patch(leftRedzoneAddr, kAllocaRedzoneSize, kAsanAllocaLeftMagic);
    FastPoisonShadowPartialRightRedzone_nid_no_patch(partialRzAligned, partialRzAddr % 8, rightRzAddr - partialRzAligned, kAsanAllocaRightMagic);
    FastPoisonShadow_nid_no_patch(rightRzAddr, kAllocaRedzoneSize, kAsanAllocaRightMagic);
}

void __asan_allocas_unpoison_nid_no_patch(std::uintptr_t top, std::uintptr_t bottom, [[maybe_unused]] const CallSite& callSite) {
    if (top == 0 || top > bottom) return;
    const auto shadowSize = (bottom - top) >> 3;
    if (shadowSize == 0) return;
    if (bottom > (1ull << 47) ||
        (top < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && bottom > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireShadow_nid_no_patch(top, bottom - top, callSite.function);
    std::memset(reinterpret_cast<void*>(AsanRuntime::ShadowBase + (top >> 3)), 0, shadowSize);
}

void __asan_before_dynamic_init_nid_no_patch(const char* moduleName, [[maybe_unused]] const CallSite& callSite) {
    static_cast<void>(moduleName);
}

void* __asan_calloc_nid_no_patch(std::size_t count, std::size_t size, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::Calloc_nid_no_patch(count, size, callSite.pc);
}

void __asan_describe_address_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::EmitDiagnostic_nid_no_patch(AsanRuntime::DescribeAddress_nid_no_patch(address, 1));
}

void __asan_exp_load1_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 1, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_load16_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 16, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_load16_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 16, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_load1_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 1, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_load2_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 2, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_load2_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 2, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_load4_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 4, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_load4_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 4, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_load8_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 8, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_load8_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 8, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_loadN_nid_no_patch(std::uintptr_t address, std::uintptr_t size, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckRegion_nid_no_patch(address, size, false, callSite.pc, callSite.bp);
}

void __asan_exp_loadN_noabort_nid_no_patch(std::uintptr_t address, std::uintptr_t size, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckRegion_nid_no_patch(address, size, false, callSite.pc, callSite.bp);
}

void __asan_exp_store1_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 1, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_store16_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 16, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_store16_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 16, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_store1_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 1, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_store2_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 2, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_store2_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 2, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_store4_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 4, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_store4_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 4, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_store8_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 8, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_store8_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 8, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_exp_storeN_nid_no_patch(std::uintptr_t address, std::uintptr_t size, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckRegion_nid_no_patch(address, size, true, callSite.pc, callSite.bp);
}

void __asan_exp_storeN_noabort_nid_no_patch(std::uintptr_t address, std::uintptr_t size, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    CheckRegion_nid_no_patch(address, size, true, callSite.pc, callSite.bp);
}

void __asan_free_nid_no_patch(void* pointer, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Heap::Deallocate_nid_no_patch(pointer, callSite.pc);
}

std::uintptr_t __asan_get_alloc_stack_nid_no_patch(std::uintptr_t address, std::uintptr_t* trace, std::uintptr_t size, std::uint32_t* threadId, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Heap::ChunkView view{};
    if (!AsanRuntime::Heap::FindChunk_nid_no_patch(address, view) || false) {
        return 0;
    }
    if (threadId) {
        *threadId = view.allocTid;
    }
    if (!trace || size == 0) {
        return 0;
    }
    trace[0] = view.allocPc - 1;
    return 1;
}

void* __asan_get_current_fake_stack_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::FakeStack::Current_nid_no_patch();
}

std::uintptr_t __asan_get_free_stack_nid_no_patch(std::uintptr_t address, std::uintptr_t* trace, std::uintptr_t size, std::uint32_t* threadId, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Heap::ChunkView view{};
    if (!AsanRuntime::Heap::FindChunk_nid_no_patch(address, view) || !view.quarantined) {
        return 0;
    }
    if (threadId) {
        *threadId = view.freeTid;
    }
    if (!trace || size == 0) {
        return 0;
    }
    trace[0] = view.freePc - 1;
    return 1;
}

std::size_t __asan_get_report_access_size_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    if (!AsanRuntime::CurrentErrorReport_nid_no_patch()->generic) {
        return 0;
    }
    return AsanRuntime::CurrentErrorReport_nid_no_patch()->accessSize;
}

int __asan_get_report_access_type_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    if (!AsanRuntime::CurrentErrorReport_nid_no_patch()->generic) {
        return 0;
    }
    return AsanRuntime::CurrentErrorReport_nid_no_patch()->isWrite ? 1 : 0;
}

void* __asan_get_report_address_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    if (!AsanRuntime::CurrentErrorReport_nid_no_patch()->generic) {
        return nullptr;
    }
    return reinterpret_cast<void*>(AsanRuntime::CurrentErrorReport_nid_no_patch()->address);
}

void* __asan_get_report_bp_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    if (!AsanRuntime::CurrentErrorReport_nid_no_patch()->generic) {
        return nullptr;
    }
    return reinterpret_cast<void*>(AsanRuntime::CurrentErrorReport_nid_no_patch()->bp);
}

const char* __asan_get_report_description_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    if (!AsanRuntime::CurrentErrorReport_nid_no_patch()->generic) {
        return nullptr;
    }
    return AsanRuntime::CurrentErrorReport_nid_no_patch()->description;
}

void* __asan_get_report_pc_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    if (!AsanRuntime::CurrentErrorReport_nid_no_patch()->generic) {
        return nullptr;
    }
    return reinterpret_cast<void*>(AsanRuntime::CurrentErrorReport_nid_no_patch()->pc);
}

void* __asan_get_report_sp_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    if (!AsanRuntime::CurrentErrorReport_nid_no_patch()->generic) {
        return nullptr;
    }
    return reinterpret_cast<void*>(AsanRuntime::CurrentErrorReport_nid_no_patch()->sp);
}

void __asan_get_shadow_mapping_nid_no_patch(std::size_t* scale, std::size_t* offset, [[maybe_unused]] const CallSite& callSite) {
    if (scale) *scale = 3;
    if (offset) *offset = AsanRuntime::ShadowBase;
}

void __asan_handle_no_return_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::HandleNoReturn_nid_no_patch();
}

void __asan_init_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    if (!AsanRuntime::InitializeShadow_nid_no_patch()) {
        ShadowUnavailable_nid_no_patch(callSite.function);
    }
}

void __asan_load1_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 1, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_load16_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 16, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_load16_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 16, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_load1_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 1, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_load2_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 2, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_load2_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 2, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_load4_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 4, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_load4_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 4, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_load8_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 8, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_load8_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 8, false, callSite.pc, callSite.bp, callSite.function);
}

void __asan_loadN_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    CheckRegion_nid_no_patch(address, size, false, callSite.pc, callSite.bp);
}

void __asan_loadN_noabort_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    CheckRegion_nid_no_patch(address, size, false, callSite.pc, callSite.bp);
}

std::uintptr_t __asan_load_cxx_array_cookie_nid_no_patch(std::uintptr_t* p, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t address = reinterpret_cast<std::uintptr_t>(p);
    if (address + 8 < address || address + 8 > (1ULL << 47) ||
        (address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && address + 8 > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireShadow_nid_no_patch(address, 8, callSite.function);
    std::uint8_t sval = *reinterpret_cast<std::uint8_t*>(AsanRuntime::ShadowBase + (address >> 3));
    if (sval == kAsanArrayCookieMagic) {
        return *p;
    }
    if (sval == kAsanHeapFreeMagic) {
        APS5_LOG_CHARS_ERR("AddressSanitizer: loaded array cookie from free-d memory; expect a double-free report");
        return 0;
    }
    return *p;
}

const char* __asan_locate_address_nid_no_patch(std::uintptr_t address, char* name, std::uintptr_t nameSize, std::uintptr_t* regionAddress, std::uintptr_t* regionSize, [[maybe_unused]] const CallSite& callSite) {
    const AsanRuntime::RegionInfo region = AsanRuntime::LocateRegion_nid_no_patch(address);
    if (name && nameSize > 0) {
        const std::size_t length = std::min<std::size_t>(region.name.size(), nameSize - 1);
        std::memcpy(name, region.name.data(), length);
        name[length] = 0;
    }
    if (regionAddress) {
        *regionAddress = region.begin;
    }
    if (regionSize) {
        *regionSize = region.size;
    }
    return region.kind;
}

void* __asan_malloc_nid_no_patch(std::size_t size, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::Allocate_nid_no_patch(size, 8, callSite.pc, true);
}

std::size_t __asan_malloc_usable_size_nid_no_patch(const void* pointer, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::UsableSize_nid_no_patch(pointer, callSite.pc);
}

void* __asan_memalign_nid_no_patch(std::size_t alignment, std::size_t size, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::Memalign_nid_no_patch(alignment, size, callSite.pc);
}

void* __asan_memcpy_nid_no_patch(void* to, const void* from, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    const auto destination = reinterpret_cast<std::uintptr_t>(to);
    const auto source = reinterpret_cast<std::uintptr_t>(from);
    if (to != from && RangesOverlap_nid_no_patch(destination, size, source, size)) {
        ReportRangesOverlap_nid_no_patch("memcpy", destination, size, source, size);
    }
    AccessRange_nid_no_patch(source, size, false, callSite.pc, callSite.bp);
    AccessRange_nid_no_patch(destination, size, true, callSite.pc, callSite.bp);
    return std::memcpy(to, from, size);
}

void* __asan_memmove_nid_no_patch(void* to, const void* from, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AccessRange_nid_no_patch(reinterpret_cast<std::uintptr_t>(from), size, false, callSite.pc, callSite.bp);
    AccessRange_nid_no_patch(reinterpret_cast<std::uintptr_t>(to), size, true, callSite.pc, callSite.bp);
    return std::memmove(to, from, size);
}

void* __asan_memset_nid_no_patch(void* block, int value, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AccessRange_nid_no_patch(reinterpret_cast<std::uintptr_t>(block), size, true, callSite.pc, callSite.bp);
    return std::memset(block, value, size);
}

void __asan_poison_cxx_array_cookie_nid_no_patch(std::uintptr_t p, [[maybe_unused]] const CallSite& callSite) {
    if (p + 1 < p || p + 1 > (1ULL << 47) ||
        (p < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && p + 1 > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireShadow_nid_no_patch(p, 1, callSite.function);
    if (!kPoisonArrayCookie) {
        return;
    }
    *reinterpret_cast<std::int8_t*>(AsanRuntime::ShadowBase + (p >> 3)) = static_cast<std::int8_t>(kAsanArrayCookieMagic);
}

void __asan_poison_intra_object_redzone_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    UpdateIntraObjectShadow_nid_no_patch(address, size, true, callSite.function);
}

void __asan_poison_memory_region_nid_no_patch(const volatile void* addr, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (!kAllowUserPoisoning || size == 0) {
        return;
    }
    std::uintptr_t begAddr = reinterpret_cast<std::uintptr_t>(addr);
    std::uintptr_t endAddr = begAddr + size;
    if (endAddr < begAddr || endAddr > (1ULL << 47) ||
        (begAddr < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && endAddr > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireShadow_nid_no_patch(begAddr, size + 1, callSite.function);
    ShadowSegmentEndpoint beg(begAddr);
    ShadowSegmentEndpoint end(endAddr);
    if (beg.chunk == end.chunk) {
        std::int8_t value = beg.value;
        if (value > 0 && value <= end.offset) {
            if (beg.offset > 0) {
                *beg.chunk = std::min(value, beg.offset);
            } else {
                *beg.chunk = kAsanUserPoisonedMemoryMagic;
            }
        }
        return;
    }
    if (beg.offset > 0) {
        if (beg.value == 0) {
            *beg.chunk = beg.offset;
        } else {
            *beg.chunk = std::min(beg.value, beg.offset);
        }
        beg.chunk++;
    }
    std::memset(beg.chunk, static_cast<unsigned char>(kAsanUserPoisonedMemoryMagic), end.chunk - beg.chunk);
    if (end.value > 0 && end.value <= end.offset) {
        *end.chunk = kAsanUserPoisonedMemoryMagic;
    }
}

void __asan_poison_stack_memory_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (size == 0) {
        return;
    }
    if ((address & 7) != 0 || address + size < address || address + size > (1ULL << 47) ||
        (address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && address + size > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireShadow_nid_no_patch(address, size, callSite.function);
    UpdateStackShadow_nid_no_patch(reinterpret_cast<std::int8_t*>(AsanRuntime::ShadowBase), AsanRuntime::ShadowSize, address, size, true);
}

int __asan_posix_memalign_nid_no_patch(void** memptr, std::size_t alignment, std::size_t size, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::PosixMemalign_nid_no_patch(memptr, alignment, size, callSite.pc);
}

void __asan_print_accumulated_stats_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::EmitDiagnostic_nid_no_patch(AsanRuntime::Heap::FormatStats_nid_no_patch());
}

void* __asan_realloc_nid_no_patch(void* pointer, std::size_t size, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::Reallocate_nid_no_patch(pointer, size, callSite.pc);
}

std::uintptr_t __asan_region_is_poisoned_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (size == 0) return 0;
    const auto end = address + size;
    if (end < address || end >= (1ull << 47) ||
        (address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && end > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireShadow_nid_no_patch(address, size, callSite.function);
    return FindFirstPoisoned_nid_no_patch(reinterpret_cast<const std::int8_t*>(AsanRuntime::ShadowBase), AsanRuntime::ShadowSize, address, size).value_or(0);
}

void __asan_register_elf_globals_nid_no_patch(std::uintptr_t* flag, void* start, void* stop, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Globals::RegisterRange_nid_no_patch(flag, start, stop);
}

void __asan_register_globals_nid_no_patch(void* globals, std::uintptr_t count, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Globals::Register_nid_no_patch(static_cast<AsanRuntime::Globals::Global*>(globals), count);
}

void __asan_report_error_nid_no_patch(void* pc, void* bp, void* sp, void* address, int isWrite, std::size_t accessSize, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    ReportGenericError_nid_no_patch(reinterpret_cast<std::uintptr_t>(pc), reinterpret_cast<std::uintptr_t>(bp), reinterpret_cast<std::uintptr_t>(sp), reinterpret_cast<std::uintptr_t>(address), isWrite != 0, accessSize);
}

void __asan_report_exp_load1_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 1);
}

void __asan_report_exp_load16_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 16);
}

void __asan_report_exp_load16_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 16);
}

void __asan_report_exp_load1_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 1);
}

void __asan_report_exp_load2_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 2);
}

void __asan_report_exp_load2_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 2);
}

void __asan_report_exp_load4_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 4);
}

void __asan_report_exp_load4_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 4);
}

void __asan_report_exp_load8_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 8);
}

void __asan_report_exp_load8_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 8);
}

void __asan_report_exp_load_n_nid_no_patch(std::uintptr_t address, std::uintptr_t size, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, size);
}

void __asan_report_exp_load_n_noabort_nid_no_patch(std::uintptr_t address, std::uintptr_t size, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, size);
}

void __asan_report_exp_store1_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 1);
}

void __asan_report_exp_store16_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 16);
}

void __asan_report_exp_store16_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 16);
}

void __asan_report_exp_store1_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 1);
}

void __asan_report_exp_store2_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 2);
}

void __asan_report_exp_store2_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 2);
}

void __asan_report_exp_store4_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 4);
}

void __asan_report_exp_store4_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 4);
}

void __asan_report_exp_store8_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 8);
}

void __asan_report_exp_store8_noabort_nid_no_patch(std::uintptr_t address, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 8);
}

void __asan_report_exp_store_n_nid_no_patch(std::uintptr_t address, std::uintptr_t size, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, size);
}

void __asan_report_exp_store_n_noabort_nid_no_patch(std::uintptr_t address, std::uintptr_t size, std::uint32_t, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, size);
}

void __asan_report_load1_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 1);
}

void __asan_report_load16_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 16);
}

void __asan_report_load16_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 16);
}

void __asan_report_load1_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 1);
}

void __asan_report_load2_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 2);
}

void __asan_report_load2_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 2);
}

void __asan_report_load4_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 4);
}

void __asan_report_load4_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 4);
}

void __asan_report_load8_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 8);
}

void __asan_report_load8_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, 8);
}

void __asan_report_load_n_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, size);
}

void __asan_report_load_n_noabort_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, false, size);
}

int __asan_report_present_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    const auto* report = AsanRuntime::CurrentErrorReport_nid_no_patch();
    return report->generic || report->other ? 1 : 0;
}

void __asan_report_store1_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 1);
}

void __asan_report_store16_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 16);
}

void __asan_report_store16_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 16);
}

void __asan_report_store1_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 1);
}

void __asan_report_store2_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 2);
}

void __asan_report_store2_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 2);
}

void __asan_report_store4_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 4);
}

void __asan_report_store4_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 4);
}

void __asan_report_store8_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 8);
}

void __asan_report_store8_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, 8);
}

void __asan_report_store_n_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, size);
}

void __asan_report_store_n_noabort_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t local = 0;
    ReportGenericError_nid_no_patch(callSite.pc, callSite.bp, reinterpret_cast<std::uintptr_t>(&local), address, true, size);
}

void __asan_set_error_report_callback_nid_no_patch(void (APS5_VABI* callback)(const char*), [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::errorReportCallback.store(callback, std::memory_order_release);
}

void __asan_set_shadow_00_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0x00, size);
}

void __asan_set_shadow_01_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0x01, size);
}

void __asan_set_shadow_02_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0x02, size);
}

void __asan_set_shadow_03_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0x03, size);
}

void __asan_set_shadow_04_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0x04, size);
}

void __asan_set_shadow_05_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0x05, size);
}

void __asan_set_shadow_06_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0x06, size);
}

void __asan_set_shadow_07_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0x07, size);
}

void __asan_set_shadow_f1_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0xf1, size);
}

void __asan_set_shadow_f2_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0xf2, size);
}

void __asan_set_shadow_f3_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0xf3, size);
}

void __asan_set_shadow_f5_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0xf5, size);
}

void __asan_set_shadow_f8_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (address == 0 || size > std::numeric_limits<std::uintptr_t>::max() - address) InvalidArgument_nid_no_patch(callSite.function);
    if (address + size > AsanRuntime::ShadowBase && address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && !AsanRuntime::ShadowRangeAvailable_nid_no_patch(std::max(address, AsanRuntime::ShadowBase), std::min(address + size, AsanRuntime::ShadowBase + AsanRuntime::ShadowSize))) ShadowUnavailable_nid_no_patch(callSite.function);
    if (size) std::memset(reinterpret_cast<void*>(address), 0xf8, size);
}

void __asan_stack_free_0_nid_no_patch(std::uintptr_t pointer, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::Free_nid_no_patch(pointer, 0, size);
}

void __asan_stack_free_1_nid_no_patch(std::uintptr_t pointer, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::Free_nid_no_patch(pointer, 1, size);
}

void __asan_stack_free_10_nid_no_patch(std::uintptr_t pointer, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::Free_nid_no_patch(pointer, 10, size);
}

void __asan_stack_free_2_nid_no_patch(std::uintptr_t pointer, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::Free_nid_no_patch(pointer, 2, size);
}

void __asan_stack_free_3_nid_no_patch(std::uintptr_t pointer, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::Free_nid_no_patch(pointer, 3, size);
}

void __asan_stack_free_4_nid_no_patch(std::uintptr_t pointer, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::Free_nid_no_patch(pointer, 4, size);
}

void __asan_stack_free_5_nid_no_patch(std::uintptr_t pointer, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::Free_nid_no_patch(pointer, 5, size);
}

void __asan_stack_free_6_nid_no_patch(std::uintptr_t pointer, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::Free_nid_no_patch(pointer, 6, size);
}

void __asan_stack_free_7_nid_no_patch(std::uintptr_t pointer, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::Free_nid_no_patch(pointer, 7, size);
}

void __asan_stack_free_8_nid_no_patch(std::uintptr_t pointer, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::Free_nid_no_patch(pointer, 8, size);
}

void __asan_stack_free_9_nid_no_patch(std::uintptr_t pointer, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::Free_nid_no_patch(pointer, 9, size);
}

std::uintptr_t __asan_stack_malloc_0_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(0, size, false, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_1_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(1, size, false, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_10_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(10, size, false, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_2_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(2, size, false, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_3_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(3, size, false, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_4_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(4, size, false, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_5_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(5, size, false, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_6_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(6, size, false, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_7_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(7, size, false, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_8_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(8, size, false, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_9_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(9, size, false, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_always_0_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(0, size, true, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_always_1_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(1, size, true, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_always_10_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(10, size, true, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_always_2_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(2, size, true, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_always_3_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(3, size, true, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_always_4_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(4, size, true, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_always_5_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(5, size, true, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_always_6_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(6, size, true, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_always_7_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(7, size, true, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_always_8_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(8, size, true, callSite.bp));
}

std::uintptr_t __asan_stack_malloc_always_9_nid_no_patch(std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    return reinterpret_cast<std::uintptr_t>(AsanRuntime::FakeStack::Malloc_nid_no_patch(9, size, true, callSite.bp));
}

void __asan_store1_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 1, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_store16_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 16, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_store16_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 16, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_store1_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 1, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_store2_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 2, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_store2_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 2, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_store4_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 4, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_store4_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 4, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_store8_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 8, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_store8_noabort_nid_no_patch(std::uintptr_t address, [[maybe_unused]] const CallSite& callSite) {
    CheckAccess_nid_no_patch(address, 8, true, callSite.pc, callSite.bp, callSite.function);
}

void __asan_storeN_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    CheckRegion_nid_no_patch(address, size, true, callSite.pc, callSite.bp);
}

void __asan_storeN_noabort_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    CheckRegion_nid_no_patch(address, size, true, callSite.pc, callSite.bp);
}

void __asan_unpoison_intra_object_redzone_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    UpdateIntraObjectShadow_nid_no_patch(address, size, false, callSite.function);
}

void __asan_unpoison_memory_region_nid_no_patch(const volatile void* addr, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (!kAllowUserPoisoning || size == 0) {
        return;
    }
    std::uintptr_t begAddr = reinterpret_cast<std::uintptr_t>(addr);
    std::uintptr_t endAddr = begAddr + size;
    if (endAddr < begAddr || endAddr > (1ULL << 47) ||
        (begAddr < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && endAddr > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireShadow_nid_no_patch(begAddr, size + 1, callSite.function);
    ShadowSegmentEndpoint beg(begAddr);
    ShadowSegmentEndpoint end(endAddr);
    if (beg.chunk == end.chunk) {
        std::int8_t value = beg.value;
        if (value != 0) {
            *beg.chunk = std::max(value, end.offset);
        }
        return;
    }
    std::memset(beg.chunk, 0, end.chunk - beg.chunk);
    if (end.offset > 0 && end.value != 0) {
        *end.chunk = std::max(end.value, end.offset);
    }
}

void __asan_unpoison_stack_memory_nid_no_patch(std::uintptr_t address, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    if (size == 0) {
        return;
    }
    if ((address & 7) != 0 || address + size < address || address + size > (1ULL << 47) ||
        (address < AsanRuntime::ShadowBase + AsanRuntime::ShadowSize && address + size > AsanRuntime::ShadowBase)) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireShadow_nid_no_patch(address, size, callSite.function);
    UpdateStackShadow_nid_no_patch(reinterpret_cast<std::int8_t*>(AsanRuntime::ShadowBase), AsanRuntime::ShadowSize, address, size, false);
}

void __asan_unregister_elf_globals_nid_no_patch(std::uintptr_t* flag, void* start, void* stop, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Globals::UnregisterRange_nid_no_patch(flag, start, stop);
}

void __asan_unregister_globals_nid_no_patch(void* globals, std::uintptr_t count, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Globals::Unregister_nid_no_patch(static_cast<AsanRuntime::Globals::Global*>(globals), count);
}

int __asan_update_allocation_context_nid_no_patch(void* address, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::UpdateContext_nid_no_patch(reinterpret_cast<std::uintptr_t>(address), callSite.pc) ? 1 : 0;
}

void __sanitizer_annotate_contiguous_container_nid_no_patch(const void* beg, const void* end, const void* oldMid, const void* newMid, [[maybe_unused]] const CallSite& callSite) {
    const auto storageBeg = reinterpret_cast<std::uintptr_t>(beg);
    const auto storageEnd = reinterpret_cast<std::uintptr_t>(end);
    const auto oldEnd = reinterpret_cast<std::uintptr_t>(oldMid);
    const auto newEnd = reinterpret_cast<std::uintptr_t>(newMid);
    if (!(storageBeg <= oldEnd && storageBeg <= newEnd && oldEnd <= storageEnd && newEnd <= storageEnd)) {
        ReportBadContainerParams_nid_no_patch(storageBeg, storageEnd, oldEnd, newEnd);
    }
    if (storageEnd - storageBeg > AsanRuntime::kMaxContainerStorage) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireGuestRange_nid_no_patch(storageBeg, storageEnd - storageBeg + 8, callSite.function);
    AsanRuntime::AnnotateContiguous_nid_no_patch(storageBeg, storageEnd, oldEnd, newEnd);
}

void __sanitizer_annotate_double_ended_contiguous_container_nid_no_patch(const void* storageBeg, const void* storageEnd, const void* oldContainerBeg, const void* oldContainerEnd, const void* newContainerBeg, const void* newContainerEnd, [[maybe_unused]] const CallSite& callSite) {
    const auto storageBegin = reinterpret_cast<std::uintptr_t>(storageBeg);
    const auto storageLimit = reinterpret_cast<std::uintptr_t>(storageEnd);
    const auto oldBegin = reinterpret_cast<std::uintptr_t>(oldContainerBeg);
    const auto oldLimit = reinterpret_cast<std::uintptr_t>(oldContainerEnd);
    const auto newBegin = reinterpret_cast<std::uintptr_t>(newContainerBeg);
    const auto newLimit = reinterpret_cast<std::uintptr_t>(newContainerEnd);
    if (!(oldBegin <= oldLimit && newBegin <= newLimit) || !(storageBegin <= newBegin && newLimit <= storageLimit) || !(storageBegin <= oldBegin && oldLimit <= storageLimit)) {
        ReportBadDoubleEndedParams_nid_no_patch(storageBegin, storageLimit, oldBegin, oldLimit, newBegin, newLimit);
    }
    if (storageLimit - storageBegin > AsanRuntime::kMaxContainerStorage) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireGuestRange_nid_no_patch(storageBegin, storageLimit - storageBegin + 8, callSite.function);
    AsanRuntime::AnnotateDoubleEnded_nid_no_patch(storageBegin, storageLimit, oldBegin, oldLimit, newBegin, newLimit);
}

const void* __sanitizer_contiguous_container_find_bad_address_nid_no_patch(const void* beg, const void* mid, const void* end, [[maybe_unused]] const CallSite& callSite) {
    const auto first = reinterpret_cast<std::uintptr_t>(beg);
    const auto middle = reinterpret_cast<std::uintptr_t>(mid);
    const auto last = reinterpret_cast<std::uintptr_t>(end);
    if (!(first <= middle && middle <= last) || last - first > AsanRuntime::kMaxContainerStorage) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireGuestRange_nid_no_patch(first, last - first + 8, callSite.function);
    return AsanRuntime::ContiguousFindBad_nid_no_patch(first, middle, last);
}

void __sanitizer_cov_dump_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Coverage::DumpTracePcGuard_nid_no_patch();
}

void __sanitizer_cov_trace_pc_guard_nid_no_patch(std::uint32_t* guard, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Coverage::TracePcGuard_nid_no_patch(guard, callSite.pc - 1);
}

void __sanitizer_cov_trace_pc_guard_init_nid_no_patch(std::uint32_t* start, std::uint32_t* end, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Coverage::InitTracePcGuard_nid_no_patch(start, end);
}

const void* __sanitizer_double_ended_contiguous_container_find_bad_address_nid_no_patch(const void* storageBeg, const void* containerBeg, const void* containerEnd, const void* storageEnd, [[maybe_unused]] const CallSite& callSite) {
    const auto storageBegin = reinterpret_cast<std::uintptr_t>(storageBeg);
    const auto storageLimit = reinterpret_cast<std::uintptr_t>(storageEnd);
    const auto begin = reinterpret_cast<std::uintptr_t>(containerBeg);
    const auto limit = reinterpret_cast<std::uintptr_t>(containerEnd);
    if (!(storageBegin <= begin && begin <= limit && limit <= storageLimit) || storageLimit - storageBegin > AsanRuntime::kMaxContainerStorage) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    RequireGuestRange_nid_no_patch(storageBegin, storageLimit - storageBegin + 8, callSite.function);
    return AsanRuntime::DoubleEndedFindBad_nid_no_patch(storageBegin, begin, limit, storageLimit);
}

void __sanitizer_dump_coverage_nid_no_patch(const std::uintptr_t* pcs, std::uintptr_t length, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Coverage::DumpCoverage_nid_no_patch(pcs, length);
}

void __sanitizer_dump_trace_pc_guard_coverage_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Coverage::DumpTracePcGuard_nid_no_patch();
}

void __sanitizer_finish_switch_fiber_nid_no_patch(void* fakeStack, const void** bottomOld, std::uintptr_t* sizeOld, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::FinishSwitchFiber_nid_no_patch(fakeStack, bottomOld, sizeOld);
}

const void* __sanitizer_get_allocated_begin_nid_no_patch(const void* pointer, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::AllocationBegin_nid_no_patch(pointer);
}

std::size_t __sanitizer_get_allocated_size_nid_no_patch(const void* pointer, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::AllocatedSizeChecked_nid_no_patch(pointer, callSite.pc);
}

std::size_t __sanitizer_get_allocated_size_fast_nid_no_patch(const void* pointer, [[maybe_unused]] const CallSite& callSite) {
    const std::size_t size = AsanRuntime::Heap::AllocationSize_nid_no_patch(reinterpret_cast<std::uintptr_t>(pointer));
    if (size == 0) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    return size;
}

std::size_t __sanitizer_get_current_allocated_bytes_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::CurrentAllocatedBytes_nid_no_patch();
}

std::size_t __sanitizer_get_estimated_allocated_size_nid_no_patch(std::size_t size, [[maybe_unused]] const CallSite& callSite) {
    return size;
}

std::size_t __sanitizer_get_free_bytes_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::FreeBytes_nid_no_patch();
}

std::size_t __sanitizer_get_heap_size_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::HeapSize_nid_no_patch();
}

int __sanitizer_get_ownership_nid_no_patch(const void* pointer, [[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::Heap::AllocationSize_nid_no_patch(reinterpret_cast<std::uintptr_t>(pointer)) > 0 ? 1 : 0;
}

const char* __sanitizer_get_report_path_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    return AsanRuntime::ReportFile::GetPath_nid_no_patch();
}

void __sanitizer_print_stack_trace_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    std::uintptr_t frames[255];
    const std::size_t count = AsanRuntime::CaptureBacktrace_nid_no_patch(frames, 255, callSite.pc, callSite.bp);
    AsanRuntime::EmitDiagnostic_nid_no_patch(AsanRuntime::StackTrace::Print_nid_no_patch(frames, count));
}

void __sanitizer_purge_allocator_nid_no_patch([[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Heap::Purge_nid_no_patch();
}

void __sanitizer_sandbox_on_notify_nid_no_patch(void* arguments, [[maybe_unused]] const CallSite& callSite) {
    static_cast<void>(arguments);
}

void __sanitizer_set_death_callback_nid_no_patch(void (APS5_VABI* callback)(), [[maybe_unused]] const CallSite& callSite) {
    deathCallback.store(callback, std::memory_order_release);
}

void __sanitizer_set_report_fd_nid_no_patch(void* descriptor, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::ReportFile::SetDescriptor_nid_no_patch(static_cast<int>(reinterpret_cast<std::uintptr_t>(descriptor)));
}

void __sanitizer_set_report_path_nid_no_patch(const char* path, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::ReportFile::SetPath_nid_no_patch(path);
}

void __sanitizer_start_switch_fiber_nid_no_patch(void** fakeStackSave, const void* bottom, std::uintptr_t size, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::FakeStack::StartSwitchFiber_nid_no_patch(fakeStackSave, bottom, size);
}

void __sanitizer_symbolize_global_nid_no_patch(std::uintptr_t address, const char* format, char* output, std::uintptr_t outputSize, [[maybe_unused]] const CallSite& callSite) {
    static_cast<void>(address);
    static_cast<void>(format);
    if (outputSize != 0) {
        output[0] = 0;
    }
}

void __sanitizer_symbolize_pc_nid_no_patch(std::uintptr_t pc, const char* format, char* output, std::uintptr_t outputSize, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::StackTrace::Symbolize_nid_no_patch(pc, format, output, outputSize);
}

std::uint16_t __sanitizer_unaligned_load16_nid_no_patch(const void* ptr, [[maybe_unused]] const CallSite& callSite) {
    const auto addr = reinterpret_cast<std::uintptr_t>(ptr);
    if (!addr || addr + sizeof(std::uint16_t) < addr) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    CheckSmallRegion_nid_no_patch(addr, sizeof(std::uint16_t), false, callSite.pc, callSite.bp);
    std::uint16_t val;
    std::memcpy(&val, ptr, sizeof(val));
    return val;
}

std::uint32_t __sanitizer_unaligned_load32_nid_no_patch(const void* ptr, [[maybe_unused]] const CallSite& callSite) {
    const auto addr = reinterpret_cast<std::uintptr_t>(ptr);
    if (!addr || addr + sizeof(std::uint32_t) < addr) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    CheckSmallRegion_nid_no_patch(addr, sizeof(std::uint32_t), false, callSite.pc, callSite.bp);
    std::uint32_t val;
    std::memcpy(&val, ptr, sizeof(val));
    return val;
}

std::uint64_t __sanitizer_unaligned_load64_nid_no_patch(const void* ptr, [[maybe_unused]] const CallSite& callSite) {
    const auto addr = reinterpret_cast<std::uintptr_t>(ptr);
    if (!addr || addr + sizeof(std::uint64_t) < addr) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    CheckSmallRegion_nid_no_patch(addr, sizeof(std::uint64_t), false, callSite.pc, callSite.bp);
    std::uint64_t val;
    std::memcpy(&val, ptr, sizeof(val));
    return val;
}

void __sanitizer_unaligned_store16_nid_no_patch(void* ptr, std::uint16_t val, [[maybe_unused]] const CallSite& callSite) {
    const auto addr = reinterpret_cast<std::uintptr_t>(ptr);
    if (!addr || addr + sizeof(val) < addr) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    CheckSmallRegion_nid_no_patch(addr, sizeof(val), true, callSite.pc, callSite.bp);
    std::memcpy(ptr, &val, sizeof(val));
}

void __sanitizer_unaligned_store32_nid_no_patch(void* ptr, std::uint32_t val, [[maybe_unused]] const CallSite& callSite) {
    const auto addr = reinterpret_cast<std::uintptr_t>(ptr);
    if (!addr || addr + sizeof(val) < addr) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    CheckSmallRegion_nid_no_patch(addr, sizeof(val), true, callSite.pc, callSite.bp);
    std::memcpy(ptr, &val, sizeof(val));
}

void __sanitizer_unaligned_store64_nid_no_patch(void* ptr, std::uint64_t val, [[maybe_unused]] const CallSite& callSite) {
    const auto addr = reinterpret_cast<std::uintptr_t>(ptr);
    if (!addr || addr + sizeof(val) < addr) {
        InvalidArgument_nid_no_patch(callSite.function);
    }
    CheckSmallRegion_nid_no_patch(addr, sizeof(val), true, callSite.pc, callSite.bp);
    std::memcpy(ptr, &val, sizeof(val));
}

int __sanitizer_verify_contiguous_container_nid_no_patch(const void* beg, const void* mid, const void* end, [[maybe_unused]] const CallSite& callSite) {
    return __sanitizer_contiguous_container_find_bad_address_nid_no_patch(beg, mid, end) == nullptr ? 1 : 0;
}

int __sanitizer_verify_double_ended_contiguous_container_nid_no_patch(const void* storageBeg, const void* containerBeg, const void* containerEnd, const void* storageEnd, [[maybe_unused]] const CallSite& callSite) {
    return __sanitizer_double_ended_contiguous_container_find_bad_address_nid_no_patch(storageBeg, containerBeg, containerEnd, storageEnd) == nullptr ? 1 : 0;
}

void __ubsan_get_current_report_data_nid_no_patch(const char** issueKind, const char** message, const char** filename, unsigned* line, unsigned* column, char** memoryAddress, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::GetCurrentReportData_nid_no_patch(issueKind, message, filename, line, column, memoryAddress);
}

void __ubsan_handle_add_overflow_nid_no_patch(void* data, std::uintptr_t lhs, std::uintptr_t rhs, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::AddOverflow, data, lhs, rhs, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_add_overflow_abort_nid_no_patch(void* data, std::uintptr_t lhs, std::uintptr_t rhs, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::AddOverflow, data, lhs, rhs, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_alignment_assumption_nid_no_patch(void* data, std::uintptr_t pointer, std::uintptr_t alignment, std::uintptr_t offset, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::AlignmentAssumption, data, pointer, alignment, offset, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_alignment_assumption_abort_nid_no_patch(void* data, std::uintptr_t pointer, std::uintptr_t alignment, std::uintptr_t offset, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::AlignmentAssumption, data, pointer, alignment, offset, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_builtin_unreachable_nid_no_patch(void* data, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::BuiltinUnreachable, data, 0, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_divrem_overflow_nid_no_patch(void* data, std::uintptr_t lhs, std::uintptr_t rhs, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::DivremOverflow, data, lhs, rhs, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_divrem_overflow_abort_nid_no_patch(void* data, std::uintptr_t lhs, std::uintptr_t rhs, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::DivremOverflow, data, lhs, rhs, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_float_cast_overflow_nid_no_patch(void* data, std::uintptr_t from, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::FloatCastOverflow, data, from, 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_float_cast_overflow_abort_nid_no_patch(void* data, std::uintptr_t from, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::FloatCastOverflow, data, from, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_function_type_mismatch_nid_no_patch(void* data, std::uintptr_t function, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::FunctionTypeMismatch, data, function, 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_function_type_mismatch_abort_nid_no_patch(void* data, std::uintptr_t function, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::FunctionTypeMismatch, data, function, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_implicit_conversion_nid_no_patch(void* data, std::uintptr_t source, std::uintptr_t destination, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::ImplicitConversion, data, source, destination, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_implicit_conversion_abort_nid_no_patch(void* data, std::uintptr_t source, std::uintptr_t destination, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::ImplicitConversion, data, source, destination, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_invalid_builtin_nid_no_patch(void* data, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::InvalidBuiltin, data, 0, 0, 0, true, callSite.pc, callSite.bp);
}

void __ubsan_handle_invalid_builtin_abort_nid_no_patch(void* data, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::InvalidBuiltin, data, 0, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_load_invalid_value_nid_no_patch(void* data, std::uintptr_t value, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::LoadInvalidValue, data, value, 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_load_invalid_value_abort_nid_no_patch(void* data, std::uintptr_t value, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::LoadInvalidValue, data, value, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_missing_return_nid_no_patch(void* data, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::MissingReturn, data, 0, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_mul_overflow_nid_no_patch(void* data, std::uintptr_t lhs, std::uintptr_t rhs, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::MulOverflow, data, lhs, rhs, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_mul_overflow_abort_nid_no_patch(void* data, std::uintptr_t lhs, std::uintptr_t rhs, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::MulOverflow, data, lhs, rhs, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_negate_overflow_nid_no_patch(void* data, std::uintptr_t oldValue, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::NegateOverflow, data, oldValue, 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_negate_overflow_abort_nid_no_patch(void* data, std::uintptr_t oldValue, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::NegateOverflow, data, oldValue, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_nonnull_arg_nid_no_patch(void* data, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::NonNullArg, data, 0, 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_nonnull_arg_abort_nid_no_patch(void* data, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::NonNullArg, data, 0, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_nonnull_return_nid_no_patch(void* data, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::LegacyNonNullReturn, data, 0, 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_nonnull_return_abort_nid_no_patch(void* data, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::LegacyNonNullReturn, data, 0, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_nonnull_return_v1_nid_no_patch(void* data, void* location, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::NonNullReturn, data, reinterpret_cast<std::uintptr_t>(location), 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_nonnull_return_v1_abort_nid_no_patch(void* data, void* location, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::NonNullReturn, data, reinterpret_cast<std::uintptr_t>(location), 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_nullability_arg_nid_no_patch(void* data, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::NullabilityArg, data, 0, 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_nullability_arg_abort_nid_no_patch(void* data, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::NullabilityArg, data, 0, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_nullability_return_v1_nid_no_patch(void* data, void* location, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::NullabilityReturn, data, reinterpret_cast<std::uintptr_t>(location), 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_nullability_return_v1_abort_nid_no_patch(void* data, void* location, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::NullabilityReturn, data, reinterpret_cast<std::uintptr_t>(location), 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_out_of_bounds_nid_no_patch(void* data, std::uintptr_t index, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::OutOfBounds, data, index, 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_out_of_bounds_abort_nid_no_patch(void* data, std::uintptr_t index, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::OutOfBounds, data, index, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_pointer_overflow_nid_no_patch(void* data, std::uintptr_t base, std::uintptr_t result, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::PointerOverflow, data, base, result, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_pointer_overflow_abort_nid_no_patch(void* data, std::uintptr_t base, std::uintptr_t result, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::PointerOverflow, data, base, result, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_shift_out_of_bounds_nid_no_patch(void* data, std::uintptr_t lhs, std::uintptr_t rhs, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::ShiftOutOfBounds, data, lhs, rhs, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_shift_out_of_bounds_abort_nid_no_patch(void* data, std::uintptr_t lhs, std::uintptr_t rhs, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::ShiftOutOfBounds, data, lhs, rhs, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_sub_overflow_nid_no_patch(void* data, std::uintptr_t lhs, std::uintptr_t rhs, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::SubOverflow, data, lhs, rhs, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_sub_overflow_abort_nid_no_patch(void* data, std::uintptr_t lhs, std::uintptr_t rhs, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::SubOverflow, data, lhs, rhs, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_type_mismatch_nid_no_patch(void* data, std::uintptr_t pointer, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::LegacyTypeMismatch, data, pointer, 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_type_mismatch_abort_nid_no_patch(void* data, std::uintptr_t pointer, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::LegacyTypeMismatch, data, pointer, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_type_mismatch_v1_nid_no_patch(void* data, std::uintptr_t pointer, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::TypeMismatch, data, pointer, 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_type_mismatch_v1_abort_nid_no_patch(void* data, std::uintptr_t pointer, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::TypeMismatch, data, pointer, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

void __ubsan_handle_vla_bound_not_positive_nid_no_patch(void* data, std::uintptr_t bound, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::VlaBound, data, bound, 0, 0, false, callSite.pc, callSite.bp);
}

void __ubsan_handle_vla_bound_not_positive_abort_nid_no_patch(void* data, std::uintptr_t bound, [[maybe_unused]] const CallSite& callSite) {
    AsanRuntime::Ubsan::Handle_nid_no_patch(AsanRuntime::Ubsan::Check::VlaBound, data, bound, 0, 0, true, callSite.pc, callSite.bp);
    Die_nid_no_patch();
}

}
