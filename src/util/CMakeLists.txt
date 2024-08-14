set (TARGET util)
aux_source_directory(. SRC)
include_directories(./include)

set (EXTDIR "${CMAKE_SOURCE_DIR}/extern")
include_directories("${EXTDIR}/lua/include")
include_directories("${EXTDIR}/unix_sys/include")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib")
add_library(${TARGET} STATIC ${SRC})
