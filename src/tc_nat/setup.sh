#!/bin/bash

# 创建网络命名空间和接口
create_network() {
    echo "Creating network namespaces..."
    sudo ip netns add lb
    sudo ip netns add ns1
    sudo ip netns add ns2
    sudo ip netns add ns3

    # 创建 veth 对
    echo "Creating veth pairs..."
    sudo ip link add veth0 type veth peer name veth-bpf
    sudo ip link add veth1-p type veth peer name veth1
    sudo ip link add veth2-p type veth peer name veth2
    sudo ip link add veth3-p type veth peer name veth3

    # 将 veth 的一端分配到命名空间
    echo "Assigning veth interfaces to namespaces..."
    sudo ip link set veth-bpf netns lb
    sudo ip link set veth1-p netns lb
    sudo ip link set veth1 netns ns1
    sudo ip link set veth2-p netns lb
    sudo ip link set veth2 netns ns2
    sudo ip link set veth3-p netns lb
    sudo ip link set veth3 netns ns3

    # 配置 host 网络接口
    echo "Configuring host network interface..."
    sudo ip addr add 192.168.50.2/24 dev veth0
    sudo ip link set veth0 up

    # 配置 lb 网络命名空间
    echo "Configuring 'lb' namespace..."
    sudo ip netns exec lb ip addr add 192.168.50.3/24 dev veth-bpf
    sudo ip netns exec lb ip addr add 172.10.1.1/24 dev veth1-p
    sudo ip netns exec lb ip addr add 172.10.2.1/24 dev veth2-p
    sudo ip netns exec lb ip addr add 172.10.3.1/24 dev veth3-p
    sudo ip netns exec lb ip link set veth-bpf up
    sudo ip netns exec lb ip link set veth1-p up
    sudo ip netns exec lb ip link set veth2-p up
    sudo ip netns exec lb ip link set veth3-p up
    sudo ip netns exec lb ip link set lo up

    # 配置 ns1 网络命名空间
    echo "Configuring 'ns1' namespace..."
    sudo ip netns exec ns1 ip addr add 172.10.1.2/24 dev veth1
    sudo ip netns exec ns1 ip link set veth1 up
    sudo ip netns exec ns1 ip link set lo up

    # 配置 ns2 网络命名空间
    echo "Configuring 'ns2' namespace..."
    sudo ip netns exec ns2 ip addr add 172.10.2.2/24 dev veth2
    sudo ip netns exec ns2 ip link set veth2 up
    sudo ip netns exec ns2 ip link set lo up

    # 配置 ns3 网络命名空间
    echo "Configuring 'ns3' namespace..."
    sudo ip netns exec ns3 ip addr add 172.10.3.2/24 dev veth3
    sudo ip netns exec ns3 ip link set veth3 up
    sudo ip netns exec ns3 ip link set lo up

    # 配置路由
    echo "Configuring routes for namespaces..."
    sudo ip netns exec ns1 ip route add default via 172.10.1.1
    sudo ip netns exec ns2 ip route add default via 172.10.2.1
    sudo ip netns exec ns3 ip route add default via 172.10.3.1

    echo "Network setup completed successfully."
}

# 删除网络命名空间和接口
delete_network() {
    echo "Deleting network namespaces..."

    # 删除命名空间和接口
    sudo ip netns del lb &> /dev/null
    sudo ip netns del ns1 &> /dev/null
    sudo ip netns del ns2 &> /dev/null
    sudo ip netns del ns3 &> /dev/null

    # 删除 veth 接口
    echo "Deleting veth pairs..."
    sudo ip link delete veth0 &> /dev/null
    sudo ip link delete veth1-p &> /dev/null
    sudo ip link delete veth2-p &> /dev/null
    sudo ip link delete veth3-p &> /dev/null

    echo "Network setup deleted successfully."
}

# 提示用户选择操作
echo "Enter your choice:"
echo "1. Create network"
echo "2. Delete network"
echo "3. Exit"

# 读取用户输入
read -p "Please select an option [1-3]: " choice

case $choice in
    1)
        create_network
        ;;
    2)
        delete_network
        ;;
    3)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice! Exiting..."
        exit 1
        ;;
esac
