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
<<<<<<< Updated upstream
CMAKE_SOURCE_DIR = /home/tianyi/Server

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/tianyi/Server/build
=======
CMAKE_SOURCE_DIR = /mydata/Server

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mydata/Server/build
>>>>>>> Stashed changes

# Include any dependencies generated for this target.
include CMakeFiles/lab1-server-shared.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/lab1-server-shared.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/lab1-server-shared.dir/flags.make

<<<<<<< Updated upstream
CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o: CMakeFiles/lab1-server-shared.dir/flags.make
CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o: ../lab1-server.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tianyi/Server/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o -c /home/tianyi/Server/lab1-server.cpp

CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tianyi/Server/lab1-server.cpp > CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.i

CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tianyi/Server/lab1-server.cpp -o CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.s
=======
CMakeFiles/lab1-server-shared.dir/lab1-server.c.o: CMakeFiles/lab1-server-shared.dir/flags.make
CMakeFiles/lab1-server-shared.dir/lab1-server.c.o: ../lab1-server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mydata/Server/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/lab1-server-shared.dir/lab1-server.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/lab1-server-shared.dir/lab1-server.c.o   -c /mydata/Server/lab1-server.c

CMakeFiles/lab1-server-shared.dir/lab1-server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/lab1-server-shared.dir/lab1-server.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mydata/Server/lab1-server.c > CMakeFiles/lab1-server-shared.dir/lab1-server.c.i

CMakeFiles/lab1-server-shared.dir/lab1-server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/lab1-server-shared.dir/lab1-server.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mydata/Server/lab1-server.c -o CMakeFiles/lab1-server-shared.dir/lab1-server.c.s
>>>>>>> Stashed changes

# Object files for target lab1-server-shared
lab1__server__shared_OBJECTS = \
"CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o"

# External object files for target lab1-server-shared
lab1__server__shared_EXTERNAL_OBJECTS =

lab1-server-shared: CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o
lab1-server-shared: CMakeFiles/lab1-server-shared.dir/build.make
lab1-server-shared: CMakeFiles/lab1-server-shared.dir/link.txt
<<<<<<< Updated upstream
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/tianyi/Server/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable lab1-server-shared"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/lab1-server-shared.dir/link.txt --verbose=$(VERBOSE)
	/usr/bin/cmake -E create_symlink lab1-server-shared /home/tianyi/Server/build/lab1-server
=======
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mydata/Server/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable lab1-server-shared"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/lab1-server-shared.dir/link.txt --verbose=$(VERBOSE)
	/usr/bin/cmake -E create_symlink lab1-server-shared /mydata/Server/build/lab1-server
>>>>>>> Stashed changes

# Rule to build all files generated by this target.
CMakeFiles/lab1-server-shared.dir/build: lab1-server-shared

.PHONY : CMakeFiles/lab1-server-shared.dir/build

CMakeFiles/lab1-server-shared.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/lab1-server-shared.dir/cmake_clean.cmake
.PHONY : CMakeFiles/lab1-server-shared.dir/clean

CMakeFiles/lab1-server-shared.dir/depend:
<<<<<<< Updated upstream
	cd /home/tianyi/Server/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tianyi/Server /home/tianyi/Server /home/tianyi/Server/build /home/tianyi/Server/build /home/tianyi/Server/build/CMakeFiles/lab1-server-shared.dir/DependInfo.cmake --color=$(COLOR)
=======
	cd /mydata/Server/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mydata/Server /mydata/Server /mydata/Server/build /mydata/Server/build /mydata/Server/build/CMakeFiles/lab1-server-shared.dir/DependInfo.cmake --color=$(COLOR)
>>>>>>> Stashed changes
.PHONY : CMakeFiles/lab1-server-shared.dir/depend

