#!/usr/bin/env python3
"""
MeltScan CLI - Versão linha de comando
"""

import argparse
import socket
import sys
import ipaddress
import re
from typing import List

# Try to import scapy
try:
    from scapy.all import IP, TCP, UDP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def parse_targets(text: str) -> List[str]:
    """Analisa alvos (IPs ou redes CIDR)"""
    raw = re.split(r"[\n,;]+", text.strip())
    out = []
    for token in raw:
        t = token.strip()
        if not t:
            continue
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
                for ip in net.hosts():
                    out.append(str(ip))
            except Exception:
                try:
                    ipaddress.ip_address(t)
                    out.append(t)
                except Exception:
                    continue
        else:
            out.append(t)
    return out

def parse_ports(text: str) -> List[int]:
    """Analisa portas (lista ou intervalos)"""
    if not text:
        return []
    parts = re.split(r"[\s,;]+", text.strip())
    ports = set()
    for p in parts:
        if not p:
            continue
        if "-" in p:
            try:
                a, b = p.split("-")
                a = int(a)
                b = int(b)
                if a < 1:
                    a = 1
                if b > 65535:
                    b = 65535
                for port in range(min(a, b), max(a, b) + 1):
                    ports.add(port)
            except Exception:
                continue
        else:
            try:
                val = int(p)
                if 1 <= val <= 65535:
                    ports.add(val)
            except Exception:
                continue
    return sorted(list(ports))

def tcp_connect_scan(target, port, timeout):
    """Scan TCP por conexão"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return "open" if result == 0 else "closed", ""
    except Exception as e:
        return "unknown", str(e)

def tcp_syn_scan(target, port, timeout):
    """Scan TCP SYN (requer Scapy)"""
    if not SCAPY_AVAILABLE:
        return tcp_connect_scan(target, port, timeout)
    try:
        conf.verb = 0
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout)
        if resp is None:
            return "filtered", "Sem resposta"
        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags & 0x12 == 0x12:
                return "open", ""
            elif flags & 0x14 == 0x14:
                return "closed", ""
        return "filtered", "Resposta inesperada"
    except Exception as e:
        return "unknown", str(e)

def udp_scan(target, port, timeout):
    """Scan UDP (requer Scapy)"""
    if not SCAPY_AVAILABLE:
        return "unknown", "Scapy não disponível"
    try:
        conf.verb = 0
        pkt = IP(dst=target) / UDP(dport=port)
        resp = sr1(pkt, timeout=timeout)
        if resp is None:
            return "open|filtered", "Sem resposta"
        elif resp.haslayer(UDP):
            return "open", ""
        else:
            return "filtered", "Provavelmente filtrada"
    except Exception as e:
        return "unknown", str(e)

def main():
    parser = argparse.ArgumentParser(description="MeltScan CLI - Scanner de portas")
    parser.add_argument("target", help="Alvo(s) (IP, lista de IPs ou rede CIDR)")
    parser.add_argument("-p", "--ports", required=True, help="Portas a escanear (ex: 80,443 ou 20-100)")
    parser.add_argument("-t", "--tcp", action="store_true", help="Scan TCP")
    parser.add_argument("-u", "--udp", action="store_true", help="Scan UDP")
    parser.add_argument("--syn", action="store_true", help="Usar scan SYN (TCP apenas)")
    parser.add_argument("--timeout", type=float, default=2, help="Timeout em segundos")
    parser.add_argument("-o", "--output", help="Arquivo para salvar resultados")
    
    args = parser.parse_args()
    
    if not args.tcp and not args.udp:
        print("Erro: Especifique pelo menos um protocolo (--tcp ou --udp)")
        sys.exit(1)
    
    # Parse targets and ports
    targets = parse_targets(args.target)
    ports = parse_ports(args.ports)
    
    if not targets:
        print("Erro: Nenhum alvo válido especificado")
        sys.exit(1)
        
    if not ports:
        print("Erro: Nenhuma porta válida especificada")
        sys.exit(1)
    
    print(f"Iniciando varredura de {len(targets)} alvo(s) e {len(ports)} porta(s)")
    print("=" * 60)
    
    results = []
    
    for target in targets:
        print(f"\nAlvo: {target}")
        for port in ports:
            if args.tcp:
                if args.syn:
                    state, info = tcp_syn_scan(target, port, args.timeout)
                else:
                    state, info = tcp_connect_scan(target, port, args.timeout)
                
                results.append(f"{target}\tTCP\t{port}\t{state}\t{info}")
                print(f"Porta {port}/TCP: {state} {f'({info})' if info else ''}")
            
            if args.udp:
                state, info = udp_scan(target, port, args.timeout)
                results.append(f"{target}\tUDP\t{port}\t{state}\t{info}")
                print(f"Porta {port}/UDP: {state} {f'({info})' if info else ''}")
    
    # Salvar resultados se solicitado
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write("Alvo\tProtocolo\tPorta\tEstado\tInfo\n")
                for result in results:
                    f.write(result + "\n")
            print(f"\nResultados salvos em: {args.output}")
        except Exception as e:
            print(f"Erro ao salvar resultados: {e}")

if __name__ == "__main__":
    main()