#!/bin/bash

# 创建网络命名空间和接口
create_network() {
    echo "Creating network namespaces..."
    for ns in lb ns1 ns2 ns3; do
        sudo ip netns add "$ns"
    done

    # 创建 veth 对
    echo "Creating veth pairs..."
    sudo ip link add "veth0" type veth peer name "veth-bpf"
    for i in {1..3}; do
        sudo ip link add "veth${i}-p" type veth peer name "veth$i"
    done

    # 将 veth 的一端分配到命名空间
    echo "Assigning veth interfaces to namespaces..."
    sudo ip link set veth-bpf netns lb
    for i in {1..3}; do
        sudo ip link set "veth${i}-p" netns lb
        sudo ip link set "veth$i" netns "ns$i"
    done

    # 配置 host 网络接口
    echo "Configuring host network interface..."
    sudo ip addr add 192.168.50.2/24 dev veth0
    sudo ip link set veth0 up

    # 配置 lb 网络命名空间
    echo "Configuring 'lb' namespace..."
    sudo ip netns exec lb bash -c '
        ip addr add 192.168.50.3/24 dev veth-bpf
        ip addr add 172.10.1.1/24 dev veth1-p
        ip addr add 172.10.2.1/24 dev veth2-p
        ip addr add 172.10.3.1/24 dev veth3-p
        ip link set veth-bpf up
        ip link set veth1-p up
        ip link set veth2-p up
        ip link set veth3-p up
        ip link set lo up
    '

    # 配置网络命名空间
    for i in {1..3}; do
        echo "Configuring 'ns$i' namespace..."
        sudo ip netns exec "ns$i" bash -c "
            ip addr add 172.10.$i.2/24 dev veth$i
            ip link set veth$i up
            ip link set lo up
            ip route add default via 172.10.$i.1
        "
    done

    echo "Network setup completed successfully."
}

# 删除网络命名空间和接口
delete_network() {
    echo "Deleting network namespaces..."
    for ns in lb ns1 ns2 ns3; do
        sudo ip netns del "$ns" &> /dev/null
    done

    # 删除 veth 接口
    echo "Deleting veth pairs..."
    for i in {0..3}; do
        sudo ip link delete "veth$i" &> /dev/null
    done

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
