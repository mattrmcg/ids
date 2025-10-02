import sys, time, random
from scapy.all import IP, TCP, send

if len(sys.argv) < 4:
    print("Usage: sudo python3 send_syns.py <TARGET_IP> <NUM_PORTS> <SECONDS> [src_ip]")
    sys.exit(1)

target = sys.argv[1]
num_ports = int(sys.argv[2])
seconds = float(sys.argv[3])
src_ip = sys.argv[4] if len(sys.argv) >= 5 else None

ports = random.sample(range(1,65536), num_ports)
interval = seconds / max(1, num_ports)
print(f"Sending {num_ports} SYNs to {target} over {seconds}s (~{1/interval:.2f} pps) interval={interval:.3f}s")

for p in ports:
    ip = IP(dst=target)
    if src_ip:
        ip.src = src_ip
    tcp = TCP(dport=p, sport=random.randint(1024, 65535), flags="S", seq=random.randint(0, 0xFFFFFFFF))
    send(ip/tcp, verbose=False)
    time.sleep(interval)
print("Done")
