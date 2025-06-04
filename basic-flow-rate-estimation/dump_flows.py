import socket
import struct
import subprocess
import json

def int_to_ip(ip):
    return socket.inet_ntoa(struct.pack('!I', ip))

# Dumpear mapa con bpftool
out = subprocess.check_output(['bpftool', 'map', 'dump', 'id', '3'], text=True)
entries = json.loads(out)

print(f"{'PROTO':<5} {'SRC IP:PORT':<22} → {'DST IP:PORT':<22} | {'BYTES':>10} | {'RATE Bps':>10}")
print("-" * 80)
for entry in entries:
    k = entry['key']
    v = entry['value']
    proto = {6: 'TCP', 17: 'UDP'}.get(k['proto'], str(k['proto']))
    src = f"{int_to_ip(k['src_ip'])}:{k['src_port']}"
    dst = f"{int_to_ip(k['dst_ip'])}:{k['dst_port']}"
    print(f"{proto:<5} {src:<22} → {dst:<22} | {v['bytes']:>10} | {v['rate_bps']:>10}")
