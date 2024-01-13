cmake_minimum_required(VERSION 3.16)
project(CertificateSSL)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

if (NOT DEFINED target_platform)
    set(target_platform "Linux")
    message("设置默认平台为：${target_platform}")
endif ()

add_library(CertificateSSL_static
        STATIC
        lib/PEM.cpp
        include/PemException.h
        lib/PemData.cpp
        lib/RSATool.cpp
        )

add_executable(CertificateSSL
        main.cpp
        )
set_target_properties(CertificateSSL_static PROPERTIES OUTPUT_NAME CertificateSSL)

target_link_libraries(CertificateSSL CertificateSSL_static)

if (${target_platform} STREQUAL "Linux")
    find_package(OpenSSL REQUIRED)
    include_directories(${OPENSSL_INCLUDE_DIR})
    find_package(CURL REQUIRED)
    include_directories(${CURL_INCLUDE_DIRS})
    target_link_libraries(CertificateSSL_static ${CURL_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
elseif (${target_platform} STREQUAL "Windows")
    add_compile_definitions(WINDOWS_BUILD)
    set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
    set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
    message("变量：${OPENSSL_ROOT_DIR}")
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib64/libcrypto.lib)
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib64/libssl.lib)
    set(OPENSSL_LIBRARIES_DIR ${OPENSSL_ROOT_DIR}/lib64)
    include_directories(${OPENSSL_ROOT_DIR}/include)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    target_link_libraries(
            CertificateSSL_static
            ${OPENSSL_CRYPTO_LIBRARY}
            ${OPENSSL_SSL_LIBRARY}
    )

elseif (${target_platform} STREQUAL "Android")
    set(CMAKE_SYSTEM_NAME Android)
    set(CMAKE_SYSTEM_VERSION 23) # API level
    set(CMAKE_ANDROID_NDK /home/ling/Android/Sdk/ndk/23.1.7779620/) # Path to Android NDK
    set(CMAKE_ANDROID_STL_TYPE c++_static) # Using static C++ runtime library
    #set(CMAKE_CXX_FLAGS "-mllvm -fla -mllvm -sub -mllvm -bcf -mllvm --bcf_loop=3 -mllvm -sobf -mllvm -sub_loop=3 -mllvm -split")
    message("架构：${CMAKE_ANDROID_ARCH_ABI}")
    if (${CMAKE_ANDROID_ARCH_ABI} STREQUAL arm64-v8a)
        set(CMAKE_CXX_COMPILER ${CMAKE_ANDROID_NDK}toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android23-clang++)
    elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL armeabi-v7a)
        set(CMAKE_CXX_COMPILER ${CMAKE_ANDROID_NDK}toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi23-clang++)
    elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL x86)
        set(CMAKE_CXX_COMPILER ${CMAKE_ANDROID_NDK}toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android23-clang++)
    elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL x86_64)
        set(CMAKE_CXX_COMPILER ${CMAKE_ANDROID_NDK}toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android23-clang++)
    else ()
        message(FATAL_ERROR "无法解析的架构：${CMAKE_ANDROID_ARCH_ABI}")
    endif ()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall")

    add_library(crypto
            STATIC
            IMPORTED)

    add_library(ssl
            STATIC
            IMPORTED)

    set_target_properties( # Specifies the target library.
            crypto

            # Specifies the parameter you want to define.
            PROPERTIES IMPORTED_LOCATION

            # Provides the path to the library you want to import.
            ${CMAKE_SOURCE_DIR}/android_libs/${ANDROID_ABI}/libcrypto.a)


    set_target_properties( # Specifies the target library.
            ssl

            # Specifies the parameter you want to define.
            PROPERTIES IMPORTED_LOCATION

            # Provides the path to the library you want to import.
            ${CMAKE_SOURCE_DIR}/android_libs/${ANDROID_ABI}/libssl.a)

    target_link_libraries( # Specifies the target library.
            CertificateSSL_static
            PRIVATE
            ssl
            crypto
            )
else ()
    message("TARGET_PLATFORM: ${target_platform}")
endif ()