# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.30

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/lin17/workspace/contest/test/c/af_packet_catch

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/lin17/workspace/contest/test/c/af_packet_catch/build

# Include any dependencies generated for this target.
include src/log/CMakeFiles/log.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/log/CMakeFiles/log.dir/compiler_depend.make

# Include the progress variables for this target.
include src/log/CMakeFiles/log.dir/progress.make

# Include the compile flags for this target's objects.
include src/log/CMakeFiles/log.dir/flags.make

src/log/CMakeFiles/log.dir/logger.c.o: src/log/CMakeFiles/log.dir/flags.make
src/log/CMakeFiles/log.dir/logger.c.o: /home/lin17/workspace/contest/test/c/af_packet_catch/src/log/logger.c
src/log/CMakeFiles/log.dir/logger.c.o: src/log/CMakeFiles/log.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/lin17/workspace/contest/test/c/af_packet_catch/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/log/CMakeFiles/log.dir/logger.c.o"
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/log && /usr/sbin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/log/CMakeFiles/log.dir/logger.c.o -MF CMakeFiles/log.dir/logger.c.o.d -o CMakeFiles/log.dir/logger.c.o -c /home/lin17/workspace/contest/test/c/af_packet_catch/src/log/logger.c

src/log/CMakeFiles/log.dir/logger.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/log.dir/logger.c.i"
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/log && /usr/sbin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lin17/workspace/contest/test/c/af_packet_catch/src/log/logger.c > CMakeFiles/log.dir/logger.c.i

src/log/CMakeFiles/log.dir/logger.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/log.dir/logger.c.s"
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/log && /usr/sbin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lin17/workspace/contest/test/c/af_packet_catch/src/log/logger.c -o CMakeFiles/log.dir/logger.c.s

# Object files for target log
log_OBJECTS = \
"CMakeFiles/log.dir/logger.c.o"

# External object files for target log
log_EXTERNAL_OBJECTS =

/home/lin17/workspace/contest/test/c/af_packet_catch/lib/liblog.so: src/log/CMakeFiles/log.dir/logger.c.o
/home/lin17/workspace/contest/test/c/af_packet_catch/lib/liblog.so: src/log/CMakeFiles/log.dir/build.make
/home/lin17/workspace/contest/test/c/af_packet_catch/lib/liblog.so: src/log/CMakeFiles/log.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/lin17/workspace/contest/test/c/af_packet_catch/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C shared library /home/lin17/workspace/contest/test/c/af_packet_catch/lib/liblog.so"
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/log && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/log.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/log/CMakeFiles/log.dir/build: /home/lin17/workspace/contest/test/c/af_packet_catch/lib/liblog.so
.PHONY : src/log/CMakeFiles/log.dir/build

src/log/CMakeFiles/log.dir/clean:
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/log && $(CMAKE_COMMAND) -P CMakeFiles/log.dir/cmake_clean.cmake
.PHONY : src/log/CMakeFiles/log.dir/clean

src/log/CMakeFiles/log.dir/depend:
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lin17/workspace/contest/test/c/af_packet_catch /home/lin17/workspace/contest/test/c/af_packet_catch/src/log /home/lin17/workspace/contest/test/c/af_packet_catch/build /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/log /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/log/CMakeFiles/log.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : src/log/CMakeFiles/log.dir/depend

