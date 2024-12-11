# 查找 libbpf 库
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src/tc_nat)
set(BPF_SRC ${SRC_DIR}/tc_nat.bpf.c)
set(USER_SRC ${SRC_DIR}/tc_nat.c)

# 定义 BPF 对象文件的输出路径
set(tc_nat_BPF ${CMAKE_CURRENT_BINARY_DIR}/tc_nat.bpf.o)

# 编译 eBPF 程序为对象文件
add_custom_command(
    OUTPUT ${tc_nat_BPF}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND clang -target bpf -g -O2 -c -I${SRC_DIR} ${BPF_SRC} -o ${tc_nat_BPF}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling eBPF program: tc_nat.bpf.c"
)

# 创建 eBPF 目标
add_custom_target(tc_nat_target DEPENDS ${tc_nat_BPF})

# 编译主程序 tc_nat.c
add_executable(tc_nat ${USER_SRC})

# 确保在编译可执行文件之前编译 eBPF 程序
add_dependencies(tc_nat tc_nat_target)

# 设置包含目录，仅对 tc_nat 目标
target_include_directories(tc_nat PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
)

# 添加编译选项（来自 pkg-config）
target_compile_options(tc_nat PRIVATE ${LIBBPF_CFLAGS})

# 链接 libbpf 库和其他必要的库
target_link_libraries(tc_nat PRIVATE ${LIBBPF_LIBRARIES})

# 添加链接选项（来自 pkg-config）
target_link_options(tc_nat PRIVATE ${LIBBPF_LDFLAGS})

# 设置 RPATH，以便在运行时找到 libbpf 库
set_target_properties(tc_nat PROPERTIES
    INSTALL_RPATH "${LIBBPF_LIBRARY_DIRS}"
    BUILD_RPATH "${LIBBPF_LIBRARY_DIRS}"
)

# 安装目标和 eBPF 对象文件
install(TARGETS tc_nat RUNTIME DESTINATION bin)
install(FILES ${tc_nat_BPF} DESTINATION bin)