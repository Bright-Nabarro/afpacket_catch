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
include src/original_capture/CMakeFiles/original_capture.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/original_capture/CMakeFiles/original_capture.dir/compiler_depend.make

# Include the progress variables for this target.
include src/original_capture/CMakeFiles/original_capture.dir/progress.make

# Include the compile flags for this target's objects.
include src/original_capture/CMakeFiles/original_capture.dir/flags.make

src/original_capture/CMakeFiles/original_capture.dir/original_capture.c.o: src/original_capture/CMakeFiles/original_capture.dir/flags.make
src/original_capture/CMakeFiles/original_capture.dir/original_capture.c.o: /home/lin17/workspace/contest/test/c/af_packet_catch/src/original_capture/original_capture.c
src/original_capture/CMakeFiles/original_capture.dir/original_capture.c.o: src/original_capture/CMakeFiles/original_capture.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/lin17/workspace/contest/test/c/af_packet_catch/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/original_capture/CMakeFiles/original_capture.dir/original_capture.c.o"
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/original_capture && /usr/sbin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/original_capture/CMakeFiles/original_capture.dir/original_capture.c.o -MF CMakeFiles/original_capture.dir/original_capture.c.o.d -o CMakeFiles/original_capture.dir/original_capture.c.o -c /home/lin17/workspace/contest/test/c/af_packet_catch/src/original_capture/original_capture.c

src/original_capture/CMakeFiles/original_capture.dir/original_capture.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/original_capture.dir/original_capture.c.i"
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/original_capture && /usr/sbin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lin17/workspace/contest/test/c/af_packet_catch/src/original_capture/original_capture.c > CMakeFiles/original_capture.dir/original_capture.c.i

src/original_capture/CMakeFiles/original_capture.dir/original_capture.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/original_capture.dir/original_capture.c.s"
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/original_capture && /usr/sbin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lin17/workspace/contest/test/c/af_packet_catch/src/original_capture/original_capture.c -o CMakeFiles/original_capture.dir/original_capture.c.s

src/original_capture/CMakeFiles/original_capture.dir/output.c.o: src/original_capture/CMakeFiles/original_capture.dir/flags.make
src/original_capture/CMakeFiles/original_capture.dir/output.c.o: /home/lin17/workspace/contest/test/c/af_packet_catch/src/original_capture/output.c
src/original_capture/CMakeFiles/original_capture.dir/output.c.o: src/original_capture/CMakeFiles/original_capture.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/lin17/workspace/contest/test/c/af_packet_catch/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object src/original_capture/CMakeFiles/original_capture.dir/output.c.o"
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/original_capture && /usr/sbin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/original_capture/CMakeFiles/original_capture.dir/output.c.o -MF CMakeFiles/original_capture.dir/output.c.o.d -o CMakeFiles/original_capture.dir/output.c.o -c /home/lin17/workspace/contest/test/c/af_packet_catch/src/original_capture/output.c

src/original_capture/CMakeFiles/original_capture.dir/output.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/original_capture.dir/output.c.i"
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/original_capture && /usr/sbin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lin17/workspace/contest/test/c/af_packet_catch/src/original_capture/output.c > CMakeFiles/original_capture.dir/output.c.i

src/original_capture/CMakeFiles/original_capture.dir/output.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/original_capture.dir/output.c.s"
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/original_capture && /usr/sbin/gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lin17/workspace/contest/test/c/af_packet_catch/src/original_capture/output.c -o CMakeFiles/original_capture.dir/output.c.s

# Object files for target original_capture
original_capture_OBJECTS = \
"CMakeFiles/original_capture.dir/original_capture.c.o" \
"CMakeFiles/original_capture.dir/output.c.o"

# External object files for target original_capture
original_capture_EXTERNAL_OBJECTS =

src/original_capture/liboriginal_capture.a: src/original_capture/CMakeFiles/original_capture.dir/original_capture.c.o
src/original_capture/liboriginal_capture.a: src/original_capture/CMakeFiles/original_capture.dir/output.c.o
src/original_capture/liboriginal_capture.a: src/original_capture/CMakeFiles/original_capture.dir/build.make
src/original_capture/liboriginal_capture.a: src/original_capture/CMakeFiles/original_capture.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/lin17/workspace/contest/test/c/af_packet_catch/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C static library liboriginal_capture.a"
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/original_capture && $(CMAKE_COMMAND) -P CMakeFiles/original_capture.dir/cmake_clean_target.cmake
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/original_capture && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/original_capture.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/original_capture/CMakeFiles/original_capture.dir/build: src/original_capture/liboriginal_capture.a
.PHONY : src/original_capture/CMakeFiles/original_capture.dir/build

src/original_capture/CMakeFiles/original_capture.dir/clean:
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/original_capture && $(CMAKE_COMMAND) -P CMakeFiles/original_capture.dir/cmake_clean.cmake
.PHONY : src/original_capture/CMakeFiles/original_capture.dir/clean

src/original_capture/CMakeFiles/original_capture.dir/depend:
	cd /home/lin17/workspace/contest/test/c/af_packet_catch/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lin17/workspace/contest/test/c/af_packet_catch /home/lin17/workspace/contest/test/c/af_packet_catch/src/original_capture /home/lin17/workspace/contest/test/c/af_packet_catch/build /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/original_capture /home/lin17/workspace/contest/test/c/af_packet_catch/build/src/original_capture/CMakeFiles/original_capture.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : src/original_capture/CMakeFiles/original_capture.dir/depend

