# MeltScan 🔎

MeltScan é um scanner de portas em Python, inspirado no **Nmap**, com interface gráfica em **Tkinter**.  
Ele permite realizar varreduras TCP e UDP em alvos específicos ou em redes inteiras (CIDR), exibindo portas **abertas, fechadas ou filtradas**.  

---

## ✨ Funcionalidades

- Varredura **TCP connect()** e **TCP SYN** (quando [Scapy](https://scapy.net) está disponível).  
- Varredura **UDP** (quando Scapy está disponível).  
- Suporte a múltiplos alvos: IPs, ranges (`22,80,1000-1010`) e CIDR (`192.168.0.0/24`).  
- Interface gráfica multiplataforma (**Linux** e **Windows**).  
- Exportação dos resultados em **TXT** e **CSV**.  
- Presets de varredura estilo **Nmap**: Quick Scan, Ping Scan e Intense Scan.  
- Resultados coloridos: 🟩 Aberta | 🟥 Fechada | 🟨 Filtrada.  

---

## ⚙️ Como funciona

O MeltScan utiliza três abordagens principais para detecção de portas:  

1. **TCP connect()** → método nativo do Python usando `socket`, que tenta estabelecer conexão completa.  
   - ✅ Funciona em qualquer ambiente (Linux/Windows).  
   - ❌ Mais “barulhento” (detectável por firewalls/IDS).  

2. **TCP SYN Scan** → envia pacotes SYN (requisição de conexão) e analisa respostas com **Scapy**.  
   - ✅ Mais rápido e furtivo.  
   - ⚠️ Requer privilégios de administrador/root.  

3. **UDP Scan** → envia pacotes UDP e aguarda resposta.  
   - ✅ Detecta serviços UDP ativos.  
   - ⚠️ Requer privilégios de administrador/root e pode ser mais lento.  

Além disso:  
- A interface gráfica em Tkinter organiza os resultados em tabela.  
- Cada linha mostra **alvo, protocolo, porta, estado e informações adicionais**.  
- O usuário pode exportar os resultados em **TXT** ou **CSV**.  

---

## ⚡ Instalação e Uso

### Requisitos

- Python **3.8+**  
- Bibliotecas necessárias:  

```bash
pip install scapy
```

---

## Clonando o projeto e executando

```bash
git clone https://github.com/seuusuario/meltscan.git
cd meltscan
python meltscan.py
```

---

## Executando no Linux

Para varreduras SYN e UDP, é necessário rodar como root:

```bash
sudo python3 meltscan.py
```

---

## Executando no Windows

```bash
python meltscan.py
```

---

## 📂 Exportação de Resultados

- TXT → cada linha contém alvo, protocolo, porta, estado e informações adicionais.
- CSV → compatível com Excel, LibreOffice e Google Sheets.

---

## 📦 Compilação em Executável

Se quiser gerar um executável independente:

---

# Windows (.exe)

```bash
pip install pyinstaller
pyinstaller --onefile meltscan.py
```

O executável será gerado em:

```bash
dist/meltscan.exe
```

---

# Linux (binário ELF)

```bash
pip install pyinstaller
pyinstaller --onefile meltscan.py
```

O executável será gerado em:

```bash
dist/meltscan
```

⚠️ Importante: o .exe só roda no Windows. No Linux, você precisa gerar o binário próprio.

---

## ⚠️ Aviso Legal

Este software deve ser utilizado apenas em redes e sistemas para os quais você tenha autorização explícita.
O uso indevido pode ser considerado atividade ilegal.
Os autores não se responsabilizam por danos ou uso indevido desta ferramenta.

---

## 🙋‍♀️ Autoria

Desenvolvido por: **Lhuany Motta** [🔗 GitHub](https://github.com/LhuanyMotta)
Versão: 1.0

---

## 📝 Exemplo Prático de Uso

Escaneando o localhost nas portas 22 e 80:
1. **Execute o MeltScan:**

```bash
python meltscan.py
```

2. **No campo Alvo(s) digite:**

```bash
127.0.0.1 (Exemplo)
```

3. **No campo Portas digite:**

```bash
22,80 (Exemplo)
```

4. **Selecione TCP ou UDP e clique em Iniciar.**

5. **Visualize os resultados e exporte em TXT ou CSV após a conclusão.**

---

## 📜 Licença

Este projeto está licenciado sob a licença MIT.
