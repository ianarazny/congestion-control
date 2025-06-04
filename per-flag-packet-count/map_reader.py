#!/usr/bin/env python3
import json
import subprocess
import argparse

# Etiquetas de índice del mapa (deben coincidir con tu orden en el programa XDP)
labels = {
    0: "TCP_SYN",
    1: "TCP_ACK",
    2: "TCP_FIN",
    3: "TCP_RST",
    4: "UDP",
    5: "TCP",
    6: "IP",
    7: "ARP"
}
def decode_value(val_list):
    """Convierte una lista de bytes hexadecimales a int"""
    bytes_val = bytes(int(b, 16) for b in val_list)
    return int.from_bytes(bytes_val, 'little')

def decode_value(val_list):
    """Convierte una lista de bytes hexadecimales a int"""
    bytes_val = bytes(int(b, 16) for b in val_list)
    return int.from_bytes(bytes_val, 'little')


def get_map_dump(map_id):
    cmd = ["sudo", "bpftool", "map", "dump", "id", str(map_id), "-j"]
    try:
        output = subprocess.check_output(cmd)
        return json.loads(output)
    except subprocess.CalledProcessError as e:
        print("Error al ejecutar bpftool:", e)
        return []

def print_interpreted_map(entries):
    print("== Conteo de paquetes por tipo/flag ==")
    for entry in entries:
        key = entry.get("key")
        raw_value = entry.get("value")
        value = decode_value(raw_value)
        if isinstance(key, list):
             key = key[0]
        label = labels.get(key, f"Desconocido_{key}")
        print(f"{label:10}: {value}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interpretar salida de mapa eBPF por flags/protocolos")
    parser.add_argument("map_id", type=int, help="ID del mapa eBPF a leer")
    args = parser.parse_args()

    entries = get_map_dump(args.map_id)
    if entries:
        print_interpreted_map(entries)
    else:
        print("No se pudo leer el mapa o está vacío.")
