"""
High-Volume Synthetic Heterogeneous Log Corpus Generator.
Generates realistic logs across defense, network, cloud, host, and proprietary sensor sources.
"""

import random
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config

SAMPLE_IPS_INTERNAL = [f"10.{random.randint(0, 50)}.{random.randint(0, 254)}.{random.randint(1, 254)}" for _ in range(20)]
SAMPLE_IPS_EXTERNAL = [f"{random.randint(11, 200)}.{random.randint(0, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}" for _ in range(20)]
SAMPLE_PORTS = [22, 53, 80, 443, 8080, 8443, 3389, 5353, 9092]
SAMPLE_USERS = ["root", "admin", "analyst_sec", "svc_backup", "deployer", "operator_7"]


def generate_cisco_asa(now: datetime) -> str:
    src_ip = random.choice(SAMPLE_IPS_EXTERNAL)
    src_port = random.randint(1024, 65535)
    dst_ip = random.choice(SAMPLE_IPS_INTERNAL)
    dst_port = random.choice(SAMPLE_PORTS)
    action = random.choice(["Deny", "Built", "Teardown"])
    return f"%ASA-4-106023: {action} tcp src outside:{src_ip}/{src_port} dst inside:{dst_ip}/{dst_port} by access-group 'DEFENSE_PERIMETER'"


def generate_k8s_json(now: datetime) -> str:
    return json.dumps({
        "timestamp": now.isoformat(),
        "level": random.choice(["INFO", "WARN", "ERROR"]),
        "kubernetes": {
            "pod_name": f"threat-detector-{random.randint(1, 99)}",
            "namespace": "defense-grid",
            "host": "node-worker-01.mil"
        },
        "network": {
            "src_ip": random.choice(SAMPLE_IPS_INTERNAL),
            "dst_ip": random.choice(SAMPLE_IPS_EXTERNAL),
            "dst_port": random.choice(SAMPLE_PORTS),
            "protocol": "TCP"
        },
        "message": "Outbound connection initiated from isolated defense enclave",
        "action": "allow"
    })


def generate_cef(now: datetime) -> str:
    src = random.choice(SAMPLE_IPS_EXTERNAL)
    dst = random.choice(SAMPLE_IPS_INTERNAL)
    spt = random.randint(1024, 65535)
    dpt = random.choice(SAMPLE_PORTS)
    act = random.choice(["block", "drop", "permit"])
    epoch_ms = int(now.timestamp() * 1000)
    return f"CEF:0|CyberArk|Vault|12.2|100|SecretRetrieved|5|src={src} dst={dst} spt={spt} dpt={dpt} act={act} rt={epoch_ms} suser={random.choice(SAMPLE_USERS)}"


def generate_leef(now: datetime) -> str:
    src = random.choice(SAMPLE_IPS_INTERNAL)
    dst = random.choice(SAMPLE_IPS_EXTERNAL)
    return f"LEEF:2.0|PaloAlto|PAN-OS|10.1|THREAT|\tdevTime={now.isoformat()}\tsrc={src}\tdst={dst}\tproto=tcp\tcat=vulnerability\tdstPort=443"


def generate_syslog_rfc5424(now: datetime) -> str:
    return f"<165>1 {now.isoformat()} gw-border-01 router 8941 MSG09 [authSDID@123 user=\"{random.choice(SAMPLE_USERS)}\"] Session authentication accepted"


def generate_auditd(now: datetime) -> str:
    epoch_sec = round(now.timestamp(), 3)
    audit_id = random.randint(100, 9999)
    pid = random.randint(1000, 99999)
    return f'type=SYSCALL msg=audit({epoch_sec}:{audit_id}): arch=c000003e syscall=59 success=yes pid={pid} comm="ncat" exe="/usr/bin/ncat" src_ip={random.choice(SAMPLE_IPS_INTERNAL)}'


def generate_proprietary_radar(now: datetime) -> str:
    node = f"BORDER_RADAR_NODE_{random.randint(1, 16)}"
    lat = round(32.7 + random.random(), 4)
    lon = round(74.8 + random.random(), 4)
    status = random.choice(["TRACKING", "LOCKED", "SWEEPING", "JAMMED"])
    return f"[RADAR-SIG-V4] {now.isoformat()} | NODE={node} | LAT={lat} | LON={lon} | STATUS={status} | LINK={random.choice(SAMPLE_IPS_INTERNAL)}->{random.choice(SAMPLE_IPS_EXTERNAL)}:8080 | MSG=\"Telemetry beacon active\""


def generate_corrupted_log(now: datetime) -> str:
    # Malformed garbage
    return f"\x00\xFF MALFORMED_SENSOR_STREAM | ADDR=999.888.777.666 | TIME=BAD_DATE | MSG=\"Buffer underrun \x01\x02\""


GENERATORS = [
    generate_cisco_asa,
    generate_k8s_json,
    generate_cef,
    generate_leef,
    generate_syslog_rfc5424,
    generate_auditd,
    generate_proprietary_radar,
    generate_corrupted_log
]


def generate_log_corpus(count: int = 5000) -> List[str]:
    logs = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=2)

    for i in range(count):
        t = base_time + timedelta(milliseconds=i * 50)
        gen = random.choice(GENERATORS)
        logs.append(gen(t))

    return logs


def save_test_corpus(output_dir: Path = config.BENCHMARK_CORPUS_DIR):
    output_dir.mkdir(parents=True, exist_ok=True)
    logs = generate_log_corpus(5000)
    file_path = output_dir / "heterogeneous_5k.log"
    with open(file_path, "w", encoding="utf-8") as f:
        for l in logs:
            f.write(l + "\n")
    print(f"[GEN] Generated 5,000 heterogeneous test logs at {file_path}")
    return file_path


if __name__ == "__main__":
    save_test_corpus()
