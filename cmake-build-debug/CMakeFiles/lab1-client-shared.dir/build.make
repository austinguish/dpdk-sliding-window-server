# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.29

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
CMAKE_COMMAND = /users/jiangyw/.cache/JetBrains/RemoteDev/dist/1729cdbf0ed8b_CLion-2024.2.2/bin/cmake/linux/x64/bin/cmake

# The command to remove a file.
RM = /users/jiangyw/.cache/JetBrains/RemoteDev/dist/1729cdbf0ed8b_CLion-2024.2.2/bin/cmake/linux/x64/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /users/jiangyw/Server

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /users/jiangyw/Server/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/lab1-client-shared.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/lab1-client-shared.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/lab1-client-shared.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/lab1-client-shared.dir/flags.make

CMakeFiles/lab1-client-shared.dir/lab1-client.c.o: CMakeFiles/lab1-client-shared.dir/flags.make
CMakeFiles/lab1-client-shared.dir/lab1-client.c.o: /users/jiangyw/Server/lab1-client.c
CMakeFiles/lab1-client-shared.dir/lab1-client.c.o: CMakeFiles/lab1-client-shared.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/users/jiangyw/Server/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/lab1-client-shared.dir/lab1-client.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/lab1-client-shared.dir/lab1-client.c.o -MF CMakeFiles/lab1-client-shared.dir/lab1-client.c.o.d -o CMakeFiles/lab1-client-shared.dir/lab1-client.c.o -c /users/jiangyw/Server/lab1-client.c

CMakeFiles/lab1-client-shared.dir/lab1-client.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/lab1-client-shared.dir/lab1-client.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /users/jiangyw/Server/lab1-client.c > CMakeFiles/lab1-client-shared.dir/lab1-client.c.i

CMakeFiles/lab1-client-shared.dir/lab1-client.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/lab1-client-shared.dir/lab1-client.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /users/jiangyw/Server/lab1-client.c -o CMakeFiles/lab1-client-shared.dir/lab1-client.c.s

# Object files for target lab1-client-shared
lab1__client__shared_OBJECTS = \
"CMakeFiles/lab1-client-shared.dir/lab1-client.c.o"

# External object files for target lab1-client-shared
lab1__client__shared_EXTERNAL_OBJECTS =

lab1-client-shared: CMakeFiles/lab1-client-shared.dir/lab1-client.c.o
lab1-client-shared: CMakeFiles/lab1-client-shared.dir/build.make
lab1-client-shared: CMakeFiles/lab1-client-shared.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/users/jiangyw/Server/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable lab1-client-shared"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/lab1-client-shared.dir/link.txt --verbose=$(VERBOSE)
	/users/jiangyw/.cache/JetBrains/RemoteDev/dist/1729cdbf0ed8b_CLion-2024.2.2/bin/cmake/linux/x64/bin/cmake -E create_symlink lab1-client-shared /users/jiangyw/Server/cmake-build-debug/lab1-client

# Rule to build all files generated by this target.
CMakeFiles/lab1-client-shared.dir/build: lab1-client-shared
.PHONY : CMakeFiles/lab1-client-shared.dir/build

CMakeFiles/lab1-client-shared.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/lab1-client-shared.dir/cmake_clean.cmake
.PHONY : CMakeFiles/lab1-client-shared.dir/clean

CMakeFiles/lab1-client-shared.dir/depend:
	cd /users/jiangyw/Server/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /users/jiangyw/Server /users/jiangyw/Server /users/jiangyw/Server/cmake-build-debug /users/jiangyw/Server/cmake-build-debug /users/jiangyw/Server/cmake-build-debug/CMakeFiles/lab1-client-shared.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/lab1-client-shared.dir/depend

