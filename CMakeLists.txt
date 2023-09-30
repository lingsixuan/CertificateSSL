cmake_minimum_required(VERSION 3.25)
project(CertificateSSL)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_executable(CertificateSSL
        main.cpp
        lib/PEM.cpp
        include/PemException.h
        lib/PemData.cpp
        lib/RSATool.cpp
        )

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries( # Specifies the target library.
        CertificateSSL
        PRIVATE
        ${OPENSSL_LIBRARIES}
        )
