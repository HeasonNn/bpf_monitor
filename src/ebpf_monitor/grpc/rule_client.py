import grpc
import rule_pb2
import rule_pb2_grpc
import socket
import struct

# ✅ IPv4 转换为 uint32
def ip_to_uint32(ip_str):
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

# ✅ 测试 `AddRule()`
def test_add_rule(stub):
    print("\n=== Testing AddRule ===")

    response = stub.AddRule(rule_pb2.RuleRequest(
        type=rule_pb2.RULE_IP, action=rule_pb2.ACTION_DROP, ip=ip_to_uint32("192.168.1.100")
    ))
    print(f"Add IP Rule: {response.message}")

    response = stub.AddRule(rule_pb2.RuleRequest(
        type=rule_pb2.RULE_CIDR, action=rule_pb2.ACTION_ACCEPT, 
        cidr=rule_pb2.Lpm(prefixlen=8, ip=ip_to_uint32("10.0.0.0"))
    ))
    print(f"Add CIDR Rule: {response.message}")

    response = stub.AddRule(rule_pb2.RuleRequest(
        type=rule_pb2.RULE_PORT, action=rule_pb2.ACTION_DROP, port=80
    ))
    print(f"Add Port Rule: {response.message}")

    response = stub.AddRule(rule_pb2.RuleRequest(
        type=rule_pb2.RULE_5TUPLE, action=rule_pb2.ACTION_ACCEPT,
        tuple=rule_pb2.FiveTuple(
            src_ip=ip_to_uint32("192.168.1.1"), 
            dst_ip=ip_to_uint32("10.0.0.5"),
            src_port=1234, dst_port=443, proto=6
        )
    ))
    print(f"Add 5-Tuple Rule: {response.message}")

# ✅ 测试 `DeleteRule()`
def test_delete_rule(stub):
    print("\n=== Testing DeleteRule ===")

    response = stub.DeleteRule(rule_pb2.RuleRequest(
        type=rule_pb2.RULE_IP, ip=ip_to_uint32("192.168.1.100")
    ))
    print(f"Delete IP Rule: {response.message}")

    response = stub.DeleteRule(rule_pb2.RuleRequest(
        type=rule_pb2.RULE_CIDR, cidr=rule_pb2.Lpm(prefixlen=8, ip=ip_to_uint32("10.0.0.0"))
    ))
    print(f"Delete CIDR Rule: {response.message}")

    response = stub.DeleteRule(rule_pb2.RuleRequest(
        type=rule_pb2.RULE_PORT, port=80
    ))
    print(f"Delete Port Rule: {response.message}")

    response = stub.DeleteRule(rule_pb2.RuleRequest(
        type=rule_pb2.RULE_5TUPLE,
        tuple=rule_pb2.FiveTuple(
            src_ip=ip_to_uint32("192.168.1.1"), 
            dst_ip=ip_to_uint32("10.0.0.5"),
            src_port=1234, dst_port=443, proto=6
        )
    ))
    print(f"Delete 5-Tuple Rule: {response.message}")

# ✅ 测试 `AddRuleBatch()`
def test_add_rule_batch(stub):
    print("\n=== Testing AddRuleBatch ===")

    rules = rule_pb2.RuleBatchRequest(
        rules=[
            rule_pb2.RuleRequest(type=rule_pb2.RULE_IP, action=rule_pb2.ACTION_DROP, ip=ip_to_uint32("192.168.2.200")),
            rule_pb2.RuleRequest(type=rule_pb2.RULE_CIDR, action=rule_pb2.ACTION_ACCEPT, cidr=rule_pb2.Lpm(prefixlen=16, ip=ip_to_uint32("172.16.0.0"))),
            rule_pb2.RuleRequest(type=rule_pb2.RULE_PORT, action=rule_pb2.ACTION_DROP, port=22)
        ]
    )

    response = stub.AddRuleBatch(rules)
    print(f"Batch Add Rules: {response.message}")

# ✅ 测试 `DeleteRuleBatch()`
def test_delete_rule_batch(stub):
    print("\n=== Testing DeleteRuleBatch ===")

    rules = rule_pb2.RuleBatchRequest(
        rules=[
            rule_pb2.RuleRequest(type=rule_pb2.RULE_IP, ip=ip_to_uint32("192.168.2.200")),
            rule_pb2.RuleRequest(type=rule_pb2.RULE_CIDR, cidr=rule_pb2.Lpm(prefixlen=16, ip=ip_to_uint32("172.16.0.0"))),
            rule_pb2.RuleRequest(type=rule_pb2.RULE_PORT, port=22)
        ]
    )

    response = stub.DeleteRuleBatch(rules)
    print(f"Batch Delete Rules: {response.message}")

# ✅ 测试 `ListRules()`
def test_list_rules(stub):
    print("\n=== Testing ListRules ===")

    print("Listing IP rules:")
    response = stub.ListRules(rule_pb2.RuleListRequest(type=rule_pb2.RULE_IP))
    print(response)

    print("Listing CIDR rules:")
    response = stub.ListRules(rule_pb2.RuleListRequest(type=rule_pb2.RULE_CIDR))
    print(response)

    print("Listing Port rules:")
    response = stub.ListRules(rule_pb2.RuleListRequest(type=rule_pb2.RULE_PORT))
    print(response)

    print("Listing 5-Tuple rules:")
    response = stub.ListRules(rule_pb2.RuleListRequest(type=rule_pb2.RULE_5TUPLE))
    print(response)

# ✅ 运行所有测试
def main():
    with grpc.insecure_channel("localhost:50051") as channel:
        stub = rule_pb2_grpc.RuleServiceStub(channel)
        test_add_rule(stub)
        test_delete_rule(stub)
        test_add_rule_batch(stub)
        test_delete_rule_batch(stub)
        test_list_rules(stub)

if __name__ == "__main__":
    main()
