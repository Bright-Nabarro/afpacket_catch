set (TARGET original_capture)
set (LUA "${CMAKE_SOURCE_DIR}/extern/lua")
aux_source_directory(. SRC)
include_directories(./include)
include_directories("${SRC_ROOT}/util/include")
include_directories("${LUA}/include")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib")
add_library(${TARGET} STATIC ${SRC})
target_link_libraries(${TARGET} PRIVATE util)
target_link_libraries(${TARGET} PRIVATE "${LUA}/lib/liblua.a" m dl)

