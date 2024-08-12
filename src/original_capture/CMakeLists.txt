set (TARGET original_capture)
aux_source_directory(. SRC)
include_directories(./include)
include_directories("${SRC_ROOT}/util/include")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib")
add_library(${TARGET} STATIC ${SRC})
target_link_libraries(${TARGET} PRIVATE util)
target_link_libraries(${TARGET} PRIVATE lua)

