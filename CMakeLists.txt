cmake_minimum_required(VERSION 3.23)
project(AesEncryption)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 20)

add_executable(AesEncryption main.cpp AesObject.cpp)
if (OPENSSL_FOUND)
    # Add the include directories for compiling
    target_include_directories(AesEncryption PRIVATE ${OPENSSL_INCLUDE_DIR})
    # Add the static lib for linking
    target_link_libraries(AesEncryption OpenSSL::SSL OpenSSL::Crypto)
    message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
else()
    message(STATUS "OpenSSL Not Found")
endif()

