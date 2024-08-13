set (TARGET util)
aux_source_directory(. SRC)
include_directories(./include)

set (LUADIR "${CMAKE_SOURCE_DIR}/extern/lua")
include_directories("${LUADIR}/include")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib")
add_library(${TARGET} STATIC ${SRC})
