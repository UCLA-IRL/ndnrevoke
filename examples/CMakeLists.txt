# cmake version to be used
cmake_minimum_required(VERSION 3.5)

if (HAVE_EXAMPLES)
    add_executable(example-client client.cpp)
    target_include_directories(example-client PUBLIC .)
    target_link_libraries(example-client PUBLIC ndn-revoke)

    add_executable(example-ct ct.cpp)
    target_include_directories(example-ct PUBLIC .)
    target_link_libraries(example-ct PUBLIC ndn-revoke)
endif (HAVE_EXAMPLES)

