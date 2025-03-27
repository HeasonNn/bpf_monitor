cmake_minimum_required(VERSION 3.10)
project(MyBPFProject)

# 设置编译选项
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O2 -g")

# 添加子模块
# add_subdirectory(src/network_monitor)
# add_subdirectory(src/mem_monitor)
# add_subdirectory(src/net_redirect)
# add_subdirectory(src/ebpf_nat)