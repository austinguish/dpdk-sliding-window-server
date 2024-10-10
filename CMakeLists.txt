cmake_minimum_required(VERSION 3.10)
project(lab1 CXX)

# Set the binary names
set(SERVER_NAME lab1-server)
set(CLIENT_NAME lab1-client)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Source files
set(SERVER_SOURCES lab1-server.cpp flowstate.h udp_header.h
)
set(CLIENT_SOURCES lab1-client.cpp flowstate.h
)

# Find DPDK package
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)
if(NOT DPDK_FOUND)
    message(FATAL_ERROR "DPDK not found")
endif()

# Add executable targets
add_executable(${SERVER_NAME}-shared ${SERVER_SOURCES}
        )
add_executable(${SERVER_NAME}-static ${SERVER_SOURCES}
        )
add_executable(${CLIENT_NAME}-shared ${CLIENT_SOURCES}
        )
add_executable(${CLIENT_NAME}-static ${CLIENT_SOURCES}
        )

# Set compile options
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DALLOW_EXPERIMENTAL_API -mssse3")

# Enable SIMD instructions
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -mtune=native -mssse3")

# Include directories
target_include_directories(${SERVER_NAME}-shared PRIVATE ${DPDK_INCLUDE_DIRS})
target_include_directories(${SERVER_NAME}-static PRIVATE ${DPDK_INCLUDE_DIRS})
target_include_directories(${CLIENT_NAME}-shared PRIVATE ${DPDK_INCLUDE_DIRS})
target_include_directories(${CLIENT_NAME}-static PRIVATE ${DPDK_INCLUDE_DIRS})

# Link libraries
target_link_libraries(${SERVER_NAME}-shared ${DPDK_LIBRARIES})
target_link_libraries(${SERVER_NAME}-static ${DPDK_STATIC_LIBRARIES})
target_link_libraries(${CLIENT_NAME}-shared ${DPDK_LIBRARIES})
target_link_libraries(${CLIENT_NAME}-static ${DPDK_STATIC_LIBRARIES})

# Create symlink for the main executables
add_custom_command(
    TARGET ${SERVER_NAME}-shared POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink
    $<TARGET_FILE_NAME:${SERVER_NAME}-shared>
    ${CMAKE_BINARY_DIR}/${SERVER_NAME}
)

add_custom_command(
    TARGET ${CLIENT_NAME}-shared POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink
    $<TARGET_FILE_NAME:${CLIENT_NAME}-shared>
    ${CMAKE_BINARY_DIR}/${CLIENT_NAME}
)

# Custom target for static build
add_custom_target(static
    COMMAND ${CMAKE_COMMAND} -E create_symlink
    $<TARGET_FILE_NAME:${SERVER_NAME}-static>
    ${CMAKE_BINARY_DIR}/${SERVER_NAME}
    DEPENDS ${SERVER_NAME}-static
)

# Install rules
install(TARGETS ${SERVER_NAME}-shared ${SERVER_NAME}-static ${CLIENT_NAME}-shared ${CLIENT_NAME}-static
    RUNTIME DESTINATION bin)
