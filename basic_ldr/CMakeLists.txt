cmake_minimum_required (VERSION 2.8)

project (basic_ldr)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

#include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
	main.cpp
	ntdll_detached.cpp
)

set (hdrs
	ntddk.h
	ntdll_detached.h
	shellcodes.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} )

# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )
