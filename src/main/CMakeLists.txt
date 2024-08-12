set (TARGET app)
aux_source_directory(. SRC)
include_directories(./include)
include_directories(${SRC_ROOT}/original_capture/include)
include_directories(${SRC_ROOT}/util/include)

add_executable(${TARGET} ${SRC})
target_link_libraries(${TARGET} PRIVATE original_capture)
target_link_libraries(${TARGET} PRIVATE util)

