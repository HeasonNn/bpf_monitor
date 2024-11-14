import socket
from prometheus_client import Gauge, start_http_server
import re

# 设置 Prometheus 指标
total_packets_gauge = Gauge('udp_total_packets', 'Total received packets')
pps_gauge = Gauge('udp_packets_per_second', 'Packets per second')
total_kbytes_gauge = Gauge('udp_total_kbytes', 'Total received KBytes')
mbps_gauge = Gauge('udp_mbps', 'Mbps')

def parse_and_set_metrics(data):
    """解析接收的数据并设置 Prometheus 指标"""
    try:
        # 解码数据
        decoded_data = data.decode().strip()

        # 使用空格分隔数据
        parts = re.split(r'\s+', decoded_data)
        if len(parts) == 4:
            # 去除千位分隔符，并将值转换为整数或浮点数
            total_packets = int(parts[0].replace(',', ''))
            pps = int(parts[1].replace(',', ''))
            total_kbytes = int(parts[2].replace(',', ''))
            mbps = float(parts[3].replace(',', ''))

            # 更新 Prometheus 指标
            total_packets_gauge.set(total_packets)
            pps_gauge.set(pps)
            total_kbytes_gauge.set(total_kbytes)
            mbps_gauge.set(mbps)

            # 打印解析后的数据
            print(f"Total Packets: {total_packets:,}")
            print(f"Packets per Second: {pps:,}")
            print(f"Total KBytes: {total_kbytes:,}")
            print(f"Mbps: {mbps}")
        else:
            print("Unexpected data format:", decoded_data)
    except ValueError as e:
        print(f"Failed to parse data: {e}")

def start_udp_server(host='0.0.0.0', port=9999):
    """启动 UDP 服务器以接收数据并更新 Prometheus 指标"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"UDP server listening on {host}:{port}")

    while True:
        data, addr = server_socket.recvfrom(1024)
        print("Received data from", addr)
        parse_and_set_metrics(data)

if __name__ == '__main__':
    start_http_server(9100)
    print("Prometheus server started on port 9100")

    start_udp_server()
