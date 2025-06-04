#!/bin/bash

# ⚙️ CONFIGURACIÓN
INTERFACE="${1:-enp0s3}"        # interfaz por defecto si no se pasa argumento
XDP_PROG="bfre_xdp.o"
SECTION="xdp"                   # sección con SEC("xdp") en tu código

# 1. Verificar que el archivo existe
if [[ ! -f $XDP_PROG ]]; then
  echo "❌ Archivo $XDP_PROG no encontrado."
  exit 1
fi

# 2. Montar bpffs si no está montado
if ! mountpoint -q /sys/fs/bpf; then
  echo "→ Montando bpffs en /sys/fs/bpf"
  sudo mount -t bpf bpffs /sys/fs/bpf
else
  echo "✓ bpffs ya está montado"
fi

# 3. Cargar el programa
echo "🚀 Cargando programa XDP sobre la interfaz $INTERFACE..."
sudo ip link set dev $INTERFACE xdp obj $XDP_PROG sec $SECTION

if [[ $? -ne 0 ]]; then
  echo "❌ Fallo al cargar el programa. ¿Interfaz correcta?"
  exit 1
fi

echo "✅ Programa cargado. Presioná Ctrl+C para descargar."

# 4. Esperar hasta Ctrl+C
trap cleanup INT
cleanup() {
  echo "🧹 Descargando programa de $INTERFACE..."
  sudo ip link set dev $INTERFACE xdp off
  echo "✅ Programa descargado"
  exit 0
}

# loop infinito mientras está cargado
while true; do sleep 1; done
