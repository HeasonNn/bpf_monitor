# 查找 libbpf 库
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src/net_redirect)
set(BPF_SRC ${SRC_DIR}/net_redirect.bpf.c)
set(USER_SRC ${SRC_DIR}/net_redirect.c)

# 定义 BPF 对象文件的输出路径
set(net_redirect_BPF ${CMAKE_CURRENT_BINARY_DIR}/net_redirect.bpf.o)

# 编译 eBPF 程序为对象文件
add_custom_command(
    OUTPUT ${net_redirect_BPF}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND clang -target bpf -g -O2 -c -I${SRC_DIR} ${BPF_SRC} -o ${net_redirect_BPF}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling eBPF program: net_redirect.bpf.c"
)

# 创建 eBPF 目标
add_custom_target(net_redirect_target DEPENDS ${net_redirect_BPF})

# 编译主程序 net_redirect.c
add_executable(net_redirect ${USER_SRC})

# 确保在编译可执行文件之前编译 eBPF 程序
add_dependencies(net_redirect net_redirect_target)

# 设置包含目录，仅对 net_redirect 目标
target_include_directories(net_redirect PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
)

# 添加编译选项（来自 pkg-config）
target_compile_options(net_redirect PRIVATE ${LIBBPF_CFLAGS})

# 链接 libbpf 库和其他必要的库
target_link_libraries(net_redirect PRIVATE ${LIBBPF_LIBRARIES})

# 添加链接选项（来自 pkg-config）
target_link_options(net_redirect PRIVATE ${LIBBPF_LDFLAGS})

# 设置 RPATH，以便在运行时找到 libbpf 库
set_target_properties(net_redirect PROPERTIES
    INSTALL_RPATH "${LIBBPF_LIBRARY_DIRS}"
    BUILD_RPATH "${LIBBPF_LIBRARY_DIRS}"
)

# 安装目标和 eBPF 对象文件
install(TARGETS net_redirect RUNTIME DESTINATION bin)
install(FILES ${net_redirect_BPF} DESTINATION bin)