import grpc
from concurrent import futures
import rule_pb2
import rule_pb2_grpc
import ctypes
import socket

# **C 结构体**
class FiveTuple(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("proto", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 3)
    ]

class Lpm(ctypes.Structure):
    _fields_ = [
        ("prefixlen", ctypes.c_uint32),
        ("ip", ctypes.c_uint32)
    ]

class RuleUnion(ctypes.Union):
    _fields_ = [
        ("ip", ctypes.c_uint32),
        ("cidr", Lpm),
        ("port", ctypes.c_uint16),
        ("tuple", FiveTuple)
    ]

class Rule(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("action", ctypes.c_int),
        ("u", RuleUnion)
    ]

# **加载 C 共享库**
librule = ctypes.CDLL("./build/libcore.so")

# **绑定 C API**
librule.add_rule.argtypes = [ctypes.POINTER(Rule)]
librule.add_rule.restype = ctypes.c_int

librule.delete_rule.argtypes = [ctypes.POINTER(Rule)]
librule.delete_rule.restype = ctypes.c_int

librule.add_rule_batch.argtypes = [ctypes.POINTER(Rule), ctypes.c_size_t]
librule.add_rule_batch.restype = ctypes.c_int

librule.delete_rule_batch.argtypes = [ctypes.POINTER(Rule), ctypes.c_size_t]
librule.delete_rule_batch.restype = ctypes.c_int

librule.list_rules.argtypes = [ctypes.c_int]
librule.list_rules.restype = ctypes.c_int

# **gRPC 服务器实现**
class RuleServiceImpl(rule_pb2_grpc.RuleServiceServicer):
    def AddRule(self, request, context):
        try:
            rule = self._build_rule_from_request(request)
        except Exception as e:
            return rule_pb2.RuleResponse(success=False, message=f"❌ Invalid rule: {e}")

        res = librule.add_rule(ctypes.byref(rule))
        return rule_pb2.RuleResponse(
            success=(res == 0),
            message="✅ Rule added" if res == 0 else "❌ Failed to add rule"
        )
    
    def DeleteRule(self, request, context):
        try:
            rule = self._build_rule_from_request(request)
        except Exception as e:
            return rule_pb2.RuleResponse(success=False, message=f"❌ Invalid rule: {e}")

        res = librule.delete_rule(ctypes.byref(rule))
        return rule_pb2.RuleResponse(
            success=(res == 0),
            message="✅ Rule deleted" if res == 0 else "❌ Failed to delete rule"
        )

    
    def AddRuleBatch(self, request, context):
        rules_array = (Rule * len(request.rules))()

        for i, req in enumerate(request.rules):
            print(f"[DEBUG] Rule[{i}] type={req.type} oneof={req.WhichOneof('rule_data')}")
            rules_array[i] = self._build_rule_from_request(req)
            print(f"[C DEBUG] Adding rule[{i}]: type={rules_array[i].type}")

        res = librule.add_rule_batch(rules_array, len(request.rules))
        return rule_pb2.RuleResponse(success=(res == 0), message="✅ Batch Add Success" if res == 0 else "❌ Batch Add Failed")

    def DeleteRuleBatch(self, request, context):
        rules_array = (Rule * len(request.rules))()
        for i, req in enumerate(request.rules):
            rules_array[i] = self._build_rule_from_request(req)
        res = librule.delete_rule_batch(rules_array, len(request.rules))
        return rule_pb2.RuleResponse(success=(res == 0), message="✅ Batch Delete Success" if res == 0 else "❌ Batch Delete Failed")

    def ListRules(self, request, context):
        res = librule.list_rules(request.type)
        return rule_pb2.RuleListResponse(rules=[])

    def _build_rule_from_request(self, request):
        rule = Rule()
        rule.type = request.type
        rule.action = request.action

        if request.type == rule_pb2.RULE_IP:
            rule.u.ip = request.ip

        elif request.type == rule_pb2.RULE_CIDR:
            rule.u.cidr.prefixlen = request.cidr.prefixlen
            rule.u.cidr.ip = request.cidr.ip

        elif request.type == rule_pb2.RULE_PORT:
            rule.u.port = request.port

        elif request.type == rule_pb2.RULE_5TUPLE:
            rule.u.tuple.src_ip = request.tuple.src_ip
            rule.u.tuple.dst_ip = request.tuple.dst_ip
            rule.u.tuple.src_port = request.tuple.src_port
            rule.u.tuple.dst_port = request.tuple.dst_port
            rule.u.tuple.proto = request.tuple.proto

        return rule


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    rule_pb2_grpc.add_RuleServiceServicer_to_server(RuleServiceImpl(), server)
    server.add_insecure_port("[::]:50051")
    print("🔥 gRPC Server running on port 50051...")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
