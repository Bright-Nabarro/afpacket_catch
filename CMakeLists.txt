cmake_minimum_required(VERSION 3.10)

project(af_packet_catch C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON) 	#生成compile_commands.json文件

if (ENABLE_RELEASE)
    set(CMAKE_BUILD_TYPE Release)
    add_compile_definitions(NDEBUG)     #针对assert
else()
    set(CMAKE_BUILD_TYPE Debug)
    add_compile_definitions(DEBUG)
endif()

add_compile_options(
	-Wall
	-Wextra
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(SRC_ROOT ${CMAKE_SOURCE_DIR}/src)

add_subdirectory("src/main")
add_subdirectory("src/original_capture")
#add_subdirectory("src/pcaplib_capture")
add_subdirectory("src/util")

#将clangd_custom_target复制到CMakeLists.txt所在目录
add_custom_target(move_compile_commands ALL
	COMMAND ${CMAKE_COMMAND} -E copy_if_different			#平台无关的复制命令
			"${CMAKE_BINARY_DIR}/compile_commands.json"
			"${CMAKE_CURRENT_SOURCE_DIR}/compile_commands.json"
	DEPENDS "${CMAKE_BINARY_DIR}/compile_commands.json"
)
