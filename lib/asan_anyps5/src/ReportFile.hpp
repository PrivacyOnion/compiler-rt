// AnyPS5 sanitizer runtime host integration, introduced 2026-10-30.
// SPDX-License-Identifier: GPL-2.0-only
// See LICENSE.GPL-2.0 and NOTICE in lib/asan_anyps5.

#pragma once

#include <string>

namespace AsanRuntime::ReportFile {

void SetPath_nid_no_patch(const char* path);
void SetDescriptor_nid_no_patch(int descriptor);
const char* GetPath_nid_no_patch();
void Write_nid_no_patch(const std::string& text);

}  // namespace AsanRuntime::ReportFile
