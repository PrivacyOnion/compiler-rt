add_library(compiler_rt_anyps5 OBJECT
    Runtime.cpp
    src/Allocator.cpp
    src/Coverage.cpp
    src/Describe.cpp
    src/FakeStack.cpp
    src/Globals.cpp
    src/ModuleLookup.cpp
    src/ReportFile.cpp
    src/StackBounds.cpp
    src/StackTrace.cpp
    src/Ubsan.cpp)
if(WIN32)
    target_sources(compiler_rt_anyps5 PRIVATE src/ShadowWindows.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(compiler_rt_anyps5 PRIVATE src/ShadowLinux.cpp)
endif()
target_compile_features(compiler_rt_anyps5 PUBLIC cxx_std_20)
target_include_directories(compiler_rt_anyps5 PRIVATE ${ANYPS5_LIBS_INCLUDE_DIR})
target_include_directories(compiler_rt_anyps5 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
set_target_properties(compiler_rt_anyps5 PROPERTIES POSITION_INDEPENDENT_CODE ON)
