#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MeltScan — Scanner de portas (GUI)
- Scans TCP (connect / syn com Scapy)
- Scans UDP (com Scapy, fallback para 'unknown' se não disponível)
- Exporta resultados para TXT e CSV
- Presets estilo "nmap" no menu
- Agora com botão "Limpar"

Aviso: use apenas em redes/equipamentos que você tem autorização para testar.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import socket
import queue
import csv
import re
import ipaddress
from typing import List

# Try to import scapy (opcional)
try:
    from scapy.all import IP, TCP, UDP, sr1, conf  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# ------------------------------
# Estruturas
# ------------------------------
class ScanResult:
    def __init__(self, target, proto, port, state, info=""):
        self.target = target
        self.proto = proto
        self.port = port
        self.state = state
        self.info = info


# ------------------------------
# Tradução e cores
# ------------------------------
def traduz_estado(state: str) -> str:
    mapping = {
        "open": "Aberta",
        "closed": "Fechada",
        "filtered": "Filtrada",
        "open|filtered": "Aberta/Filtrada",
        "timeout": "Tempo esgotado",
        "unknown": "Desconhecida",
    }
    return mapping.get(state, state)


def cor_estado(state_pt: str) -> str:
    return {
        "Aberta": "lightgreen",
        "Fechada": "salmon",
        "Filtrada": "khaki",
        "Aberta/Filtrada": "orange",
        "Tempo esgotado": "lightgray",
        "Desconhecida": "white",
    }.get(state_pt, "white")


# ------------------------------
# Parser de alvos e portas
# ------------------------------
def parse_targets(text: str) -> List[str]:
    """
    Aceita múltiplos alvos separados por vírgula, nova linha, ou ponto e vírgula.
    Suporta IPs simples e endereços no formato CIDR (ex.: 192.168.1.0/28).
    Retorna lista de endereços (IPv4/IPv6) como strings.
    """
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
    """
    Analisa entradas como: 22,80,443,1000-1010 -> lista de ints
    Ignora valores inválidos.
    """
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


# ------------------------------
# Scans
# ------------------------------
def tcp_connect_scan(target, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            return "open", ""
        else:
            return "closed", ""
    except Exception as e:
        return "unknown", str(e)


def tcp_syn_scan(target, port, timeout):
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


# ------------------------------
# Worker
# ------------------------------
def worker(taskq: queue.Queue, results: List[ScanResult], settings, logfn, stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            target, proto, port = taskq.get_nowait()
        except queue.Empty:
            break
        if stop_event.is_set():
            taskq.task_done()
            break
        if proto == "tcp":
            if settings["tcp_mode"] == "syn":
                state, info = tcp_syn_scan(target, port, settings["timeout"])
            else:
                state, info = tcp_connect_scan(target, port, settings["timeout"])
        else:
            state, info = udp_scan(target, port, settings["timeout"])
        results.append(ScanResult(target, proto, port, state, info))
        try:
            logfn(target, proto, port, state, info)
        except Exception:
            pass
        taskq.task_done()


# ------------------------------
# GUI
# ------------------------------
class MeltScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MeltScan — Scanner de Portas")

        # Menu
        menubar = tk.Menu(root)
        root.config(menu=menubar)

        menu_arquivo = tk.Menu(menubar, tearoff=0)
        menu_arquivo.add_command(label="Exportar TXT", command=self.export_txt)
        menu_arquivo.add_command(label="Exportar CSV", command=self.export_csv)
        menu_arquivo.add_separator()
        menu_arquivo.add_command(label="Sair", command=root.quit)
        menubar.add_cascade(label="Arquivo", menu=menu_arquivo)

        menu_sistema = tk.Menu(menubar, tearoff=0)
        menu_sistema.add_command(label="Quick Scan (common ports)", command=self.preset_quick)
        menu_sistema.add_command(label="Ping Scan (ICMP)", command=self.preset_ping)
        menu_sistema.add_command(label="Intense Scan (top 1-1024)", command=self.preset_intense)
        menubar.add_cascade(label="Sistema (nmap-like)", menu=menu_sistema)

        menu_ajuda = tk.Menu(menubar, tearoff=0)
        menu_ajuda.add_command(label="Sobre", command=self.sobre)
        menubar.add_cascade(label="Ajuda", menu=menu_ajuda)

        # Frame principal
        frame = ttk.Frame(root, padding=8)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Alvo(s) (CIDR, vírgula ou nova linha):").grid(row=0, column=0, sticky="w")
        self.target_entry = tk.Text(frame, height=3, width=80)
        self.target_entry.grid(row=0, column=1, columnspan=5, sticky="we", pady=2)

        ttk.Label(frame, text="Portas (ex: 22,80,1000-1010):").grid(row=1, column=0, sticky="w")
        self.ports_entry = ttk.Entry(frame, width=40)
        self.ports_entry.insert(0, "")
        self.ports_entry.grid(row=1, column=1, columnspan=2, sticky="w")

        self.tcp_var = tk.BooleanVar(value=True)
        self.udp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="TCP", variable=self.tcp_var).grid(row=1, column=3, sticky="w")
        ttk.Checkbutton(frame, text="UDP", variable=self.udp_var).grid(row=1, column=4, sticky="w")

        ttk.Label(frame, text="Modo TCP:").grid(row=2, column=0, sticky="w")
        self.tcp_mode = ttk.Combobox(frame, values=["syn", "connect"], width=10)
        self.tcp_mode.current(0)
        self.tcp_mode.grid(row=2, column=1, sticky="w")

        ttk.Label(frame, text="Timeout (s):").grid(row=2, column=2, sticky="e")
        self.timeout_spin = ttk.Spinbox(frame, from_=1, to=30, width=5)
        self.timeout_spin.set(2)
        self.timeout_spin.grid(row=2, column=3, sticky="w")

        ttk.Label(frame, text="Threads:").grid(row=2, column=4, sticky="e")
        self.threads_spin = ttk.Spinbox(frame, from_=1, to=500, width=6)
        self.threads_spin.set(50)
        self.threads_spin.grid(row=2, column=5, sticky="w")

        # Botões
        self.start_btn = ttk.Button(frame, text="Iniciar", command=self.start_scan)
        self.start_btn.grid(row=3, column=1, pady=6, sticky="w")

        self.stop_btn = ttk.Button(frame, text="Parar", command=self.stop_scan, state="disabled")
        self.stop_btn.grid(row=3, column=2, pady=6, sticky="w")

        self.clear_btn = ttk.Button(frame, text="Limpar", command=self.clear_results)
        self.clear_btn.grid(row=3, column=3, pady=6, sticky="w")

        # Resultados
        cols = ("alvo", "proto", "porta", "estado", "info")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col in cols:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=140, anchor="center")
        self.tree.grid(row=4, column=0, columnspan=6, sticky="nsew", pady=5)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=4, column=6, sticky="ns")
        self.tree.configure(yscrollcommand=vsb.set)

        frame.rowconfigure(4, weight=1)
        frame.columnconfigure(1, weight=1)

        # Barra de status
        self.status_var = tk.StringVar(value="Pronto")
        self.status_label = ttk.Label(root, textvariable=self.status_var, anchor="w")
        self.status_label.pack(fill="x", side="bottom")

        # Controle
        self.scanning = False
        self.results: List[ScanResult] = []
        self.stop_event = threading.Event()

    # ---------- Presets ----------
    def preset_quick(self):
        self.ports_entry.delete(0, "end")
        self.ports_entry.insert(0, "22,80,443,53,3389,139,445")
        self.tcp_var.set(True)
        self.udp_var.set(False)
        self.tcp_mode.set("connect")

    def preset_ping(self):
        self.ports_entry.delete(0, "end")
        self.ports_entry.insert(0, "")
        self.tcp_var.set(False)
        self.udp_var.set(False)

    def preset_intense(self):
        self.ports_entry.delete(0, "end")
        self.ports_entry.insert(0, "1-1024")
        self.tcp_var.set(True)
        self.udp_var.set(True)
        self.tcp_mode.set("syn")

    # ---------- Logging ----------
    def log_result(self, target, proto, port, state, info):
        estado_pt = traduz_estado(state)
        cor = cor_estado(estado_pt)
        self.root.after(0, lambda: self._insert_tree(target, proto, port, estado_pt, info, cor))

    def _insert_tree(self, target, proto, port, estado_pt, info, cor):
        self.tree.insert("", "end", values=(target, proto, port, estado_pt, info), tags=(estado_pt,))
        self.tree.tag_configure(estado_pt, background=cor)

    # ---------- Controle ----------
    def start_scan(self):
        if self.scanning:
            return
        targets_text = self.target_entry.get("1.0", "end").strip()
        targets = parse_targets(targets_text)
        if not targets:
            messagebox.showerror("Erro", "Nenhum alvo válido fornecido.")
            return
        ports_text = self.ports_entry.get().strip()
        ports = parse_ports(ports_text)
        if not ports and (self.tcp_var.get() or self.udp_var.get()):
            messagebox.showerror("Erro", "Nenhuma porta válida fornecida.")
            return

        self.clear_results()
        self.scanning = True
        self.stop_event.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("Varredura em andamento...")

        taskq = queue.Queue()
        for t in targets:
            for p in ports:
                if self.tcp_var.get():
                    taskq.put((t, "tcp", p))
                if self.udp_var.get():
                    taskq.put((t, "udp", p))

        settings = {"timeout": float(self.timeout_spin.get()), "tcp_mode": self.tcp_mode.get()}
        try:
            num_threads = max(1, min(500, int(self.threads_spin.get())))
        except Exception:
            num_threads = 50

        threading.Thread(target=self.run_workers, args=(taskq, settings, num_threads), daemon=True).start()

    def run_workers(self, taskq, settings, num_threads):
        threads = []
        for _ in range(max(1, min(500, num_threads))):
            th = threading.Thread(
                target=worker,
                args=(taskq, self.results, settings, self.log_result, self.stop_event),
            )
            th.start()
            threads.append(th)
        for th in threads:
            th.join()
        self.root.after(0, self.scan_done)

    def scan_done(self):
        self.scanning = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set("Concluído")

    def stop_scan(self):
        if not self.scanning:
            return
        self.stop_event.set()
        self.status_var.set("Interrompido")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.scanning = False

    def clear_results(self):
        """Limpa tabela e lista interna de resultados"""
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.status_var.set("Resultados limpos")

    # ---------- Exportação ----------
    def export_txt(self):
        if not self.results:
            messagebox.showwarning("Aviso", "Nenhum resultado para exportar.")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Arquivo de texto", "*.txt")])
        if not filepath:
            return
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                for r in self.results:
                    f.write(f"{r.target}\t{r.proto}\t{r.port}\t{traduz_estado(r.state)}\t{r.info}\n")
            messagebox.showinfo("Sucesso", f"Resultados exportados para {filepath}")
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def export_csv(self):
        if not self.results:
            messagebox.showwarning("Aviso", "Nenhum resultado para exportar.")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("Arquivo CSV", "*.csv")])
        if not filepath:
            return
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Alvo", "Protocolo", "Porta", "Estado", "Info"])
                for r in self.results:
                    writer.writerow([r.target, r.proto, r.port, traduz_estado(r.state), r.info])
            messagebox.showinfo("Sucesso", f"Resultados exportados para {filepath}")
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def sobre(self):
        info = "MeltScan — Scanner de Portas\nVersão 1.0\nInspirado no Nmap. Use apenas em redes autorizadas."
        if not SCAPY_AVAILABLE:
            info += "\n\nObservação: Scapy não detectado. Scans SYN/UDP podem não funcionar sem Scapy e privilégios de administrador/root."
        messagebox.showinfo("Sobre", info)


# ------------------------------
# Execução
# ------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = MeltScanApp(root)
    root.geometry("1000x650")
    root.mainloop()
