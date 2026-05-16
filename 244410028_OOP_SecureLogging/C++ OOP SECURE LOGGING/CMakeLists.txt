cmake_minimum_required(VERSION 3.22)
project(IlkerKuru_CyberSec CXX)

# C++20 zorunlu — jthread, std::format, std::latch, std::span, std::rotr
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Derleyici Bayrakları ───────────────────────────────────────────────────
if (MSVC)
    add_compile_options(
        /W4 /WX          # Tüm uyarılar hata sayılır
        /permissive-     # Strict C++ conformance
        /Zc:__cplusplus  # Doğru __cplusplus değeri
        /utf-8           # UTF-8 kaynak dosyaları (Türkçe yorumlar)
        /O2              # Optimizasyon
        /EHsc            # Exception handling
    )
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
        -O2
        -pthread
    )
    link_libraries(pthread)
endif()

# ─── Proje 1: SecureLogger ──────────────────────────────────────────────────
add_executable(SecureLogger
    SecureLogger/main_logger.cpp
)
target_include_directories(SecureLogger PRIVATE SecureLogger/)
set_target_properties(SecureLogger PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ─── Proje 2: EDREngine ─────────────────────────────────────────────────────
add_executable(EDREngine
    EDREngine/main_edr.cpp
)
target_include_directories(EDREngine PRIVATE EDREngine/)
set_target_properties(EDREngine PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

message(STATUS "")
message(STATUS "╔══════════════════════════════════════════╗")
message(STATUS "║  İlker Kuru CyberSec Suite — CMake OK   ║")
message(STATUS "║  C++ Standard : C++20                   ║")
message(STATUS "║  Targets      : SecureLogger, EDREngine ║")
message(STATUS "╚══════════════════════════════════════════╝")
message(STATUS "")
