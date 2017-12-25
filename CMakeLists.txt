cmake_minimum_required ( VERSION 2.8 )

project ( loaderine )

# libs
# modules:
set ( M_PARSER "libpeconv/libpeconv" )

# modules paths:
set (PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PARSER}" CACHE PATH "PEConv main path")
add_subdirectory ( ${PECONV_DIR} )
set ( PECONV_LIB $<TARGET_FILE:libpeconv> CACHE FILE "PEConvLib library path" )

# Add sub-directories
#
add_subdirectory ( basic_ldr )

#dependencies:
add_dependencies( basic_ldr libpeconv )

