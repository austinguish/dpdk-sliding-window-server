cmake_minimum_required(VERSION 3.10)
project(lab1-server C)

# Set the binary name
set(APP_NAME lab1-server)

# Source files
set(SOURCES lab1-server.c)

# Find DPDK package
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

if(NOT DPDK_FOUND)
    message(FATAL_ERROR "DPDK not found")
endif()

# Add executable targets
add_executable(${APP_NAME}-shared ${SOURCES})
add_executable(${APP_NAME}-static ${SOURCES})

# Set compile options
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Og -DALLOW_EXPERIMENTAL_API")

# Enable SIMD instructions
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native -mtune=native")

# Include directories
target_include_directories(${APP_NAME}-shared PRIVATE ${DPDK_INCLUDE_DIRS})
target_include_directories(${APP_NAME}-static PRIVATE ${DPDK_INCLUDE_DIRS})

# Link libraries
target_link_libraries(${APP_NAME}-shared ${DPDK_LIBRARIES})
target_link_libraries(${APP_NAME}-static ${DPDK_STATIC_LIBRARIES})

# Create symlink for the main executable
add_custom_command(
    TARGET ${APP_NAME}-shared POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        $<TARGET_FILE_NAME:${APP_NAME}-shared>
        ${CMAKE_BINARY_DIR}/${APP_NAME}
)

# Custom target for static build
add_custom_target(static
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        $<TARGET_FILE_NAME:${APP_NAME}-static>
        ${CMAKE_BINARY_DIR}/${APP_NAME}
    DEPENDS ${APP_NAME}-static
)

# Install rules
install(TARGETS ${APP_NAME}-shared ${APP_NAME}-static
    RUNTIME DESTINATION bin
)