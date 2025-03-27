cmake_minimum_required(VERSION 3.16)
project(ebpf_monitor)
set(CMAKE_C_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBXDP REQUIRED libxdp)

set(BPF_SRC ${CMAKE_SOURCE_DIR}/bpf/ebpf_monitor.bpf.c)
set(EBPF_MONITOR ${CMAKE_SOURCE_DIR}/src/loader.c)
set(EBPF_MAP_UPDATE ${CMAKE_SOURCE_DIR}/src/update.c)
set(ebpf_monitor_BPF ${CMAKE_CURRENT_BINARY_DIR}/ebpf_monitor.bpf.o)

add_custom_command(
    OUTPUT ${ebpf_monitor_BPF}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND clang -target bpf -g -O2 -c -I${CMAKE_SOURCE_DIR}/include ${BPF_SRC} -o ${ebpf_monitor_BPF}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling eBPF program: ebpf_monitor.bpf.c"
)

add_custom_target(ebpf_monitor_target DEPENDS ${ebpf_monitor_BPF})

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBXDP_INCLUDE_DIRS}
)

file(GLOB_RECURSE LIB_SOURCES "${CMAKE_SOURCE_DIR}/lib/*.c")
set(LIB_SOURCES  ${LIB_SOURCES})

file(GLOB_RECURSE API_SOURCES "${CMAKE_SOURCE_DIR}/api/*.c")
set(API_SOURCES  ${API_SOURCES})

# core
add_library(core SHARED 
    ${LIB_SOURCES}
    ${API_SOURCES}
)
add_dependencies(core ebpf_monitor_target)
target_link_libraries(core PRIVATE ${LIBBPF_LIBRARIES} ${LIBXDP_LIBRARIES})
target_link_options(core PRIVATE ${LIBBPF_LDFLAGS} ${LIBXDP_LDFLAGS})

# ebpf_monitor
add_executable(loader ${EBPF_MONITOR})
add_dependencies(loader core)
target_link_libraries(loader PRIVATE core)
target_compile_options(loader PRIVATE ${LIBBPF_CFLAGS} ${LIBXDP_CFLAGS})
set_target_properties(loader PROPERTIES
    INSTALL_RPATH "${LIBBPF_LIBRARY_DIRS};${LIBXDP_LIBRARY_DIRS}"
    BUILD_RPATH "${LIBBPF_LIBRARY_DIRS};${LIBXDP_LIBRARY_DIRS}"
)

# ebpf_map_update
add_executable(update ${EBPF_MAP_UPDATE})
add_dependencies(update core)
target_link_libraries(update PRIVATE core)
target_compile_options(update PRIVATE ${LIBBPF_CFLAGS} ${LIBXDP_CFLAGS})
set_target_properties(update PROPERTIES
    INSTALL_RPATH "${LIBBPF_LIBRARY_DIRS};${LIBXDP_LIBRARY_DIRS}"
    BUILD_RPATH "${LIBBPF_LIBRARY_DIRS};${LIBXDP_LIBRARY_DIRS}"
)

install(TARGETS update RUNTIME DESTINATION bin)
install(TARGETS loader RUNTIME DESTINATION bin)
install(FILES ${ebpf_monitor_BPF} DESTINATION bin)