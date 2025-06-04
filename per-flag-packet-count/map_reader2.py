#!/usr/bin/env python3
import json
import subprocess
import argparse

# Etiquetas por índice (índices enteros)
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
    """Convierte lista de bytes hexadecimales a entero little-endian"""
    bytes_val = bytes(int(b, 16) for b in val_list)
    return int.from_bytes(bytes_val, 'little')

def get_map_dump(map_id):
    """Obtiene la salida JSON de bpftool map dump"""
    cmd = ["sudo", "bpftool", "map", "dump", "id", str(map_id), "-j"]
    try:
        output = subprocess.check_output(cmd)
        return json.loads(output)
    except subprocess.CalledProcessError as e:
        print("Error al ejecutar bpftool:", e)
        return []

def print_interpreted_map(entries):
    print("== Conteo de paquetes por tipo/flag ==")
    totals = {}
    for entry in entries:
        key_raw = entry.get("key")
        raw_value = entry.get("value")

        # Normalizar clave a entero
        if isinstance(key_raw, list):
            key = key_raw[0]
        elif isinstance(key_raw, str):
            try:
                key = int(key_raw, 16 if key_raw.startswith("0x") else 10)
            except ValueError:
                print(f"Clave inválida: {key_raw}")
                continue
        else:
            key = key_raw  # ya es int

        # Decodificar valor __u64
        value = decode_value(raw_value)

        # Buscar etiqueta legible
        label = labels.get(key, f"Desconocido_0x{int(key):02x}")
        totals[label] = value
        print(f"{label:10}: {value}")

    print_summary(totals)

def print_summary(totals):
    print("\n== Resumen ==")
    ip_total = totals.get("IP", 0)
    tcp_total = totals.get("TCP", 0)
    udp_total = totals.get("UDP", 0)
    ack_total = totals.get("TCP_ACK", 0)

    if ip_total > 0:
        tcp_pct = tcp_total * 100 / ip_total
        udp_pct = udp_total * 100 / ip_total
    else:
        tcp_pct = udp_pct = 0.0

    if tcp_total > 0:
        ack_pct = ack_total * 100 / tcp_total
    else:
        ack_pct = 0.0

    print(f"Total IP        : {ip_total}")
    print(f" - TCP          : {tcp_total} ({tcp_pct:.2f}%)")
    print(f" - UDP          : {udp_total} ({udp_pct:.2f}%)")
    print(f"TCP ACK         : {ack_total} ({ack_pct:.2f}% de TCP)")
    print(f"ARP             : {totals.get('ARP', 0)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interpreta mapa eBPF por tipo/flag")
    parser.add_argument("map_id", type=int, help="ID del mapa eBPF")
    args = parser.parse_args()

    entries = get_map_dump(args.map_id)
    if entries:
        print_interpreted_map(entries)
    else:
        print("No se pudo leer el mapa o está vacío.")
