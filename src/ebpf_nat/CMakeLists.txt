find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBBPF REQUIRED libbpf)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src/ebpf_nat/src)
set(BPF_SRC ${SRC_DIR}/bpf/ebpf_nat.bpf.c)
set(APP ${SRC_DIR}/main.c)
set(ebpf_nat_BPF ${CMAKE_CURRENT_BINARY_DIR}/ebpf_nat.bpf.o)

add_custom_command(
    OUTPUT ${ebpf_nat_BPF}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND clang -target bpf -g -O2 -c -I${SRC_DIR} ${BPF_SRC} -o ${ebpf_nat_BPF}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling eBPF program: ebpf_nat.bpf.c"
)

add_custom_target(ebpf_nat_target DEPENDS ${ebpf_nat_BPF})

include_directories(
    ${SRC_DIR}/include
    ${LIBBPF_INCLUDE_DIRS}
)

set(LIB_SOURCES 
    ${SRC_DIR}/lib/ebpf_nat.c
    ${SRC_DIR}/lib/event_handler.c
)

add_library(mylib STATIC ${LIB_SOURCES})

add_executable(ebpf_nat ${APP})

add_dependencies(mylib ebpf_nat_target)
add_dependencies(ebpf_nat mylib)

target_link_libraries(mylib PRIVATE ${LIBBPF_LIBRARIES})
target_link_options(mylib PRIVATE ${LIBBPF_LDFLAGS})

target_link_libraries(ebpf_nat PRIVATE mylib event)

target_compile_options(ebpf_nat PRIVATE ${LIBBPF_CFLAGS})

set_target_properties(ebpf_nat PROPERTIES
    INSTALL_RPATH "${LIBBPF_LIBRARY_DIRS}"
    BUILD_RPATH "${LIBBPF_LIBRARY_DIRS}"
)

install(TARGETS ebpf_nat RUNTIME DESTINATION bin)
install(FILES ${ebpf_nat_BPF} DESTINATION bin)