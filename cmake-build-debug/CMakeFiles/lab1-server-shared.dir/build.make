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
CMAKE_COMMAND = /mydata/1729cdbf0ed8b_CLion-2024.2.2/bin/cmake/linux/x64/bin/cmake

# The command to remove a file.
RM = /mydata/1729cdbf0ed8b_CLion-2024.2.2/bin/cmake/linux/x64/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /mydata/Server

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mydata/Server/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/lab1-server-shared.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/lab1-server-shared.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/lab1-server-shared.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/lab1-server-shared.dir/flags.make

CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o: CMakeFiles/lab1-server-shared.dir/flags.make
CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o: /mydata/Server/lab1-server.cpp
CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o: CMakeFiles/lab1-server-shared.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/mydata/Server/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o -MF CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o.d -o CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o -c /mydata/Server/lab1-server.cpp

CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mydata/Server/lab1-server.cpp > CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.i

CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mydata/Server/lab1-server.cpp -o CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.s

CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.o: CMakeFiles/lab1-server-shared.dir/flags.make
CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.o: /mydata/Server/lab1-client.cpp
CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.o: CMakeFiles/lab1-server-shared.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/mydata/Server/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.o -MF CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.o.d -o CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.o -c /mydata/Server/lab1-client.cpp

CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mydata/Server/lab1-client.cpp > CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.i

CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mydata/Server/lab1-client.cpp -o CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.s

# Object files for target lab1-server-shared
lab1__server__shared_OBJECTS = \
"CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o" \
"CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.o"

# External object files for target lab1-server-shared
lab1__server__shared_EXTERNAL_OBJECTS =

lab1-server-shared: CMakeFiles/lab1-server-shared.dir/lab1-server.cpp.o
lab1-server-shared: CMakeFiles/lab1-server-shared.dir/lab1-client.cpp.o
lab1-server-shared: CMakeFiles/lab1-server-shared.dir/build.make
lab1-server-shared: CMakeFiles/lab1-server-shared.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/mydata/Server/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable lab1-server-shared"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/lab1-server-shared.dir/link.txt --verbose=$(VERBOSE)
	/mydata/1729cdbf0ed8b_CLion-2024.2.2/bin/cmake/linux/x64/bin/cmake -E create_symlink lab1-server-shared /mydata/Server/cmake-build-debug/lab1-server

# Rule to build all files generated by this target.
CMakeFiles/lab1-server-shared.dir/build: lab1-server-shared
.PHONY : CMakeFiles/lab1-server-shared.dir/build

CMakeFiles/lab1-server-shared.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/lab1-server-shared.dir/cmake_clean.cmake
.PHONY : CMakeFiles/lab1-server-shared.dir/clean

CMakeFiles/lab1-server-shared.dir/depend:
	cd /mydata/Server/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mydata/Server /mydata/Server /mydata/Server/cmake-build-debug /mydata/Server/cmake-build-debug /mydata/Server/cmake-build-debug/CMakeFiles/lab1-server-shared.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/lab1-server-shared.dir/depend

