# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
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
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/tianyi/Server

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/tianyi/Server/build

# Include any dependencies generated for this target.
include CMakeFiles/lab1-client-shared.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/lab1-client-shared.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/lab1-client-shared.dir/flags.make

CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.o: CMakeFiles/lab1-client-shared.dir/flags.make
CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.o: ../lab1-client.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tianyi/Server/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.o -c /home/tianyi/Server/lab1-client.cpp

CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tianyi/Server/lab1-client.cpp > CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.i

CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tianyi/Server/lab1-client.cpp -o CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.s

# Object files for target lab1-client-shared
lab1__client__shared_OBJECTS = \
"CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.o"

# External object files for target lab1-client-shared
lab1__client__shared_EXTERNAL_OBJECTS =

lab1-client-shared: CMakeFiles/lab1-client-shared.dir/lab1-client.cpp.o
lab1-client-shared: CMakeFiles/lab1-client-shared.dir/build.make
lab1-client-shared: CMakeFiles/lab1-client-shared.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/tianyi/Server/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable lab1-client-shared"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/lab1-client-shared.dir/link.txt --verbose=$(VERBOSE)
	/usr/bin/cmake -E create_symlink lab1-client-shared /home/tianyi/Server/build/lab1-client

# Rule to build all files generated by this target.
CMakeFiles/lab1-client-shared.dir/build: lab1-client-shared

.PHONY : CMakeFiles/lab1-client-shared.dir/build

CMakeFiles/lab1-client-shared.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/lab1-client-shared.dir/cmake_clean.cmake
.PHONY : CMakeFiles/lab1-client-shared.dir/clean

CMakeFiles/lab1-client-shared.dir/depend:
	cd /home/tianyi/Server/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tianyi/Server /home/tianyi/Server /home/tianyi/Server/build /home/tianyi/Server/build /home/tianyi/Server/build/CMakeFiles/lab1-client-shared.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/lab1-client-shared.dir/depend

