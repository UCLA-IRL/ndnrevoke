# cmake version to be used
cmake_minimum_required(VERSION 3.5)

# project name
project(NDNREVOKE)

# flags
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)
if (HAVE_TESTS)
    add_compile_definitions(NDNREVOKE_HAVE_TESTS)
endif(HAVE_TESTS)

# dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(NDN_CXX REQUIRED libndn-cxx)
pkg_check_modules(CERT_LEDGER REQUIRED libcert-ledger)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

# files
file(GLOB_RECURSE NDNREVOKE_LIB_SOURCE_FILES "src/*.cpp" "src/**/*.cpp")

# include
include_directories(${NDN_CXX_INCLUDE_DIRS})
include_directories(src)
include_directories(build/src)

# link
link_directories(${NDN_CXX_LIBRARY_DIRS})

# target

add_library(ndn-revoke SHARED ${NDNREVOKE_LIB_SOURCE_FILES})
target_compile_options(ndn-revoke PUBLIC ${NDN_CXX_CFLAGS} ${CERT_LEDGER_CFLAGS})
target_link_libraries(ndn-revoke PUBLIC ${NDN_CXX_LIBRARIES} ${CERT_LEDGER_LIBRARIES})

add_subdirectory(tests)
