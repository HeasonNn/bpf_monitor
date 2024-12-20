find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src/tc_nat)
set(BPF_SRC ${SRC_DIR}/tc_nat.bpf.c)
set(USER_SRC ${SRC_DIR}/tc_nat.c)

set(tc_nat_BPF ${CMAKE_CURRENT_BINARY_DIR}/tc_nat.bpf.o)

add_custom_command(
    OUTPUT ${tc_nat_BPF}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND clang -target bpf -g -O2 -c -I${SRC_DIR} ${BPF_SRC} -o ${tc_nat_BPF}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling eBPF program: tc_nat.bpf.c"
)

add_custom_target(tc_nat_target DEPENDS ${tc_nat_BPF})

add_executable(tc_nat ${USER_SRC})

add_dependencies(tc_nat tc_nat_target)

target_include_directories(tc_nat PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
)

target_compile_options(tc_nat PRIVATE ${LIBBPF_CFLAGS})

target_link_libraries(tc_nat PRIVATE ${LIBBPF_LIBRARIES})

target_link_options(tc_nat PRIVATE ${LIBBPF_LDFLAGS})

set_target_properties(tc_nat PROPERTIES
    INSTALL_RPATH "${LIBBPF_LIBRARY_DIRS}"
    BUILD_RPATH "${LIBBPF_LIBRARY_DIRS}"
)

install(TARGETS tc_nat RUNTIME DESTINATION bin)
install(FILES ${tc_nat_BPF} DESTINATION bin)