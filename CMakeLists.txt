cmake_minimum_required(VERSION 3.20)

project(ShutdownGuard
  VERSION 0.1.0
  LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)

if (MSVC)
  add_compile_options(/W4 /permissive- /EHsc)
endif()

include(FetchContent)

# MinHook (v1.3.4) without requiring git
FetchContent_Declare(
  minhook
  URL https://github.com/TsudaKageyu/minhook/archive/refs/tags/v1.3.4.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  SOURCE_SUBDIR minhook-1.3.4
)
FetchContent_MakeAvailable(minhook)

add_library(power_guard_common INTERFACE)
target_include_directories(power_guard_common INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/source-code
)
if (WIN32)
  # Toolchain mis-detect may append ".lib" to -l items; pass exact flags instead.
  target_link_options(power_guard_common INTERFACE
    -ladvapi32
    -lbcrypt
    -luserenv
    -lshell32
    -lwtsapi32
    -lole32
  )
endif()

add_executable(power_guard_service
  source-code/service/GuardServiceMain.cpp
  source-code/service/GuardPipeServer.cpp
  source-code/service/GuardPipeServer.hpp
  source-code/service/GuardProcessWatcher.cpp
  source-code/service/GuardProcessWatcher.hpp
)
target_link_libraries(power_guard_service PRIVATE power_guard_common)
if (WIN32 AND MSVC)
  # wbemuuid.lib is MSVC/Windows SDK only; MinGW/Clang use polling fallback in GuardProcessWatcher.
  target_link_libraries(power_guard_service PRIVATE wbemuuid)
endif()
set_target_properties(power_guard_service PROPERTIES OUTPUT_NAME "ShutdownGuard")
if (WIN32 AND NOT MSVC)
  target_link_options(power_guard_service PRIVATE -static)
endif()

add_executable(power_guard_ui WIN32
  source-code/ui/GuardUiMain.cpp
  source-code/ui/PasswordPromptWindow.cpp
  source-code/ui/PasswordPromptWindow.hpp
)
target_link_libraries(power_guard_ui PRIVATE power_guard_common)
set_target_properties(power_guard_ui PROPERTIES OUTPUT_NAME "ShutdownGuardUI")
if (WIN32)
  target_link_options(power_guard_ui PRIVATE -lcomctl32 -lgdi32)
endif()
if (WIN32 AND NOT MSVC)
  target_link_options(power_guard_ui PRIVATE -static)
endif()

add_library(power_guard_hookdll SHARED
  source-code/hook/HookDllMain.cpp
  source-code/hook/HookInstall.cpp
  source-code/hook/HookInstall.hpp
  source-code/hook/HookIpcClient.cpp
  source-code/hook/HookIpcClient.hpp
)
target_link_libraries(power_guard_hookdll PRIVATE power_guard_common minhook)
set_target_properties(power_guard_hookdll PROPERTIES OUTPUT_NAME "ShutdownGuardHook")
target_compile_definitions(power_guard_hookdll PRIVATE GUARD_HOOKDLL_EXPORTS)
if (WIN32 AND NOT MSVC)
  # For DLLs, -static alone does not reliably link the MinGW runtime statically.
  # The injected DLL must carry its own runtime; the target process won't have
  # libstdc++-6.dll / libgcc_s_seh-1.dll / libwinpthread-1.dll on the search path.
  target_link_options(power_guard_hookdll PRIVATE
    -static-libgcc -static-libstdc++
    -Wl,-Bstatic -lpthread -Wl,-Bdynamic
  )
endif()

add_executable(power_guard_injector
  source-code/injector/GuardInjectorMain.cpp
  source-code/injector/ProcessUtil.cpp
  source-code/injector/ProcessUtil.hpp
)
target_link_libraries(power_guard_injector PRIVATE power_guard_common)
set_target_properties(power_guard_injector PROPERTIES OUTPUT_NAME "ShutdownGuardInjector")
if (WIN32 AND NOT MSVC)
  target_link_options(power_guard_injector PRIVATE -static)
endif()

add_executable(power_guard_setup
  source-code/setup/ShutdownGuardInstallMain.cpp
)
target_link_libraries(power_guard_setup PRIVATE power_guard_common)
set_target_properties(power_guard_setup PROPERTIES OUTPUT_NAME "ShutdownGuardInstall")
if (WIN32 AND NOT MSVC)
  target_link_options(power_guard_setup PRIVATE -static)
endif()

add_executable(power_guard_uninstall
  source-code/setup/ShutdownGuardUninstallMain.cpp
  source-code/hook/HookUninstall.cpp
)
target_link_libraries(power_guard_uninstall PRIVATE power_guard_common)
set_target_properties(power_guard_uninstall PROPERTIES OUTPUT_NAME "ShutdownGuardUninstall")
if (WIN32 AND NOT MSVC)
  target_link_options(power_guard_uninstall PRIVATE -static)
endif()

