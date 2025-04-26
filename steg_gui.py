"""
Tento program umožňuje vložit a extrahovat zprávu do/ze WAV souboru.

program umožňuje vložit a extrahovat zprávu do/ze WAV souboru.

zajištění integrity zprávy pomocí hashovací funkce SHA-256.

a šifrování zprávy pomocí XOR šifrování.

Vytvořili: Nekuda a Kala 

"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import wave
import numpy as np
import hashlib
import os

def text_to_bits(text):
    """
    Převede text na binární řetězec.
    
    Args:
        text (str): Text k převodu
        
    Returns:
        str: Binární řetězec reprezentující text
    """
    # Převede text na bytes pomocí UTF-8
    bytes_data = text.encode('utf-8')
    # Převede každý byte na 8-bit binární řetězec a spojí je
    return ''.join(format(byte, '08b') for byte in bytes_data)

def bits_to_text(bits_string):
    """
    Převede binární řetězec zpět na text.
    
    Args:
        bits_string (str): Binární řetězec
        
    Returns:
        str: Původní text
        
    Raises:
        ValueError: Pokud délka bits_string není násobkem 8
        UnicodeDecodeError: Pokud bits_string neobsahuje platné UTF-8 bajty
    """
    if len(bits_string) % 8 != 0:
        raise ValueError("Délka binárního řetězce musí být násobkem 8")
    
    # Rozdělí binární řetězec na 8-bitové části
    bytes_list = []
    for i in range(0, len(bits_string), 8):
        byte = bits_string[i:i+8]
        bytes_list.append(int(byte, 2))
    
    # Převede seznam bajtů na bytes objekt a dekóduje UTF-8
    return bytes(bytes_list).decode('utf-8')

def bytes_to_bits(byte_data):
    """
    Převede bytes objekt na binární řetězec.
    
    Args:
        byte_data (bytes): Bytes objekt k převodu
        
    Returns:
        str: Binární řetězec
    """
    return ''.join(format(byte, '08b') for byte in byte_data)

def bits_to_bytes(bits_string):
    """
    Převede binární řetězec na bytes objekt.
    
    Args:
        bits_string (str): Binární řetězec
        
    Returns:
        bytes: Bytes objekt
        
    Raises:
        ValueError: Pokud délka bits_string není násobkem 8
    """
    if len(bits_string) % 8 != 0:
        raise ValueError("Délka binárního řetězce musí být násobkem 8")
    
    bytes_list = []
    for i in range(0, len(bits_string), 8):
        byte = bits_string[i:i+8]
        bytes_list.append(int(byte, 2))
    
    return bytes(bytes_list)

def generate_xor_key(password, length):
    """
    Vygeneruje XOR klíč z hesla.
    
    Args:
        password (str): Heslo pro generování klíče
        length (int): Požadovaná délka klíče v bajtech
        
    Returns:
        bytes: XOR klíč
        
    Raises:
        ValueError: Pokud je délka hesla příliš krátká nebo příliš dlouhá
    """
    if not password:
        raise ValueError("Heslo nesmí být prázdné")
    if len(password) < 4:
        raise ValueError("Heslo musí mít alespoň 4 znaky")
    if len(password) > 1000:
        raise ValueError("Heslo je příliš dlouhé (maximálně 1000 znaků)")
        
    # Vytvoří SHA-256 hash z hesla
    hash_obj = hashlib.sha256(password.encode('utf-8'))
    hash_bytes = hash_obj.digest()
    
    # Opakuje hash, dokud nedosáhne požadované délky
    key = bytearray()
    while len(key) < length:
        key.extend(hash_bytes)
    
    return bytes(key[:length])

def xor_cipher(data, key):
    """
    Provede XOR šifrování/dešifrování dat.
    
    Args:
        data (bytes): Data k šifrování/dešifrování
        key (bytes): XOR klíč
        
    Returns:
        bytes: Zašifrovaná/dešifrovaná data
    """
    if len(data) != len(key):
        raise ValueError("Délka dat a klíče musí být stejná")
    
    # Provede XOR operaci na každém bajtu
    return bytes(a ^ b for a, b in zip(data, key))

def embed(input_wav_path, output_wav_path, message, password):
    """
    Vloží tajnou zprávu do WAV souboru pomocí LSB steganografie.
    
    Args:
        input_wav_path (str): Cesta k vstupnímu WAV souboru
        output_wav_path (str): Cesta k výstupnímu WAV souboru
        message (str): Tajná zpráva k vložení
        password (str): Heslo pro šifrování
        
    Returns:
        bool: True pokud úspěšné, jinak False
        
    Raises:
        ValueError: Pokud vstupní soubor není WAV nebo má nepodporovaný formát
        IOError: Pokud nelze číst/zapisovat soubory
    """
    try:
        # Validace vstupů
        if not os.path.exists(input_wav_path):
            raise ValueError("Vstupní soubor neexistuje")
        if not input_wav_path.lower().endswith('.wav'):
            raise ValueError("Vstupní soubor musí být WAV")
        if not message or not password:
            raise ValueError("Zpráva a heslo nesmí být prázdné")
            
        # Příprava dat
        message_bytes = message.encode('utf-8')
        hash_bytes = hashlib.sha256(message_bytes).digest()
        data_to_encrypt = hash_bytes + message_bytes
        
        # Generování klíče a šifrování
        key = generate_xor_key(password, len(data_to_encrypt))
        encrypted_data = xor_cipher(data_to_encrypt, key)
        
        # Převod na bity
        encrypted_length_bits = len(encrypted_data) * 8
        length_header_bits = format(encrypted_length_bits, '032b')
        encrypted_data_bits = bytes_to_bits(encrypted_data)
        payload_bits = length_header_bits + encrypted_data_bits
        total_bits_needed = len(payload_bits)
        
        # Čtení WAV souboru
        with wave.open(input_wav_path, 'rb') as audio_file:
            n_frames = audio_file.getnframes()
            samp_width = audio_file.getsampwidth()
            n_channels = audio_file.getnchannels()
            frame_rate = audio_file.getframerate()
            
            # Kontrola formátu
            if samp_width not in [1, 2]:
                raise ValueError("Podporovány jsou pouze 8-bit a 16-bit WAV soubory")
            if samp_width == 1:  # 8-bit
                dtype = np.uint8
            else:  # 16-bit
                dtype = np.int16
                
            # Kontrola kapacity
            total_samples = n_frames * n_channels
            if total_bits_needed > total_samples:
                raise ValueError("Audio soubor je příliš krátký pro vložení zprávy")
                
            # Načtení vzorků
            frames = audio_file.readframes(n_frames)
            samples = np.frombuffer(frames, dtype=dtype).copy()
            
        # Vložení dat pomocí LSB
        for i in range(total_bits_needed):
            bit = int(payload_bits[i])
            samples[i] = (samples[i] & ~1) | bit
            
        # Zápis výstupního souboru
        with wave.open(output_wav_path, 'wb') as output_file:
            output_file.setnchannels(n_channels)
            output_file.setsampwidth(samp_width)
            output_file.setframerate(frame_rate)
            output_file.writeframes(samples.tobytes())
            
        return True
        
    except Exception as e:
        raise ValueError(f"Chyba při vkládání zprávy: {str(e)}")

def extract(input_wav_path, password):
    """
    Extrahuje tajnou zprávu z WAV souboru.
    
    Args:
        input_wav_path (str): Cesta k WAV souboru s ukrytou zprávou
        password (str): Heslo pro dešifrování
        
    Returns:
        str: Extrahovaná zpráva
        
    Raises:
        ValueError: Pokud soubor neobsahuje ukrytou zprávu nebo je heslo nesprávné
        IOError: Pokud nelze číst soubor
    """
    try:
        # Validace vstupů
        if not os.path.exists(input_wav_path):
            raise ValueError("Vstupní soubor neexistuje")
        if not input_wav_path.lower().endswith('.wav'):
            raise ValueError("Vstupní soubor musí být WAV")
        if not password:
            raise ValueError("Heslo nesmí být prázdné")
            
        # Čtení WAV souboru
        with wave.open(input_wav_path, 'rb') as audio_file:
            n_frames = audio_file.getnframes()
            samp_width = audio_file.getsampwidth()
            n_channels = audio_file.getnchannels()
            
            # Kontrola formátu
            if samp_width not in [1, 2]:
                raise ValueError("Podporovány jsou pouze 8-bit a 16-bit WAV soubory")
            if samp_width == 1:  # 8-bit
                dtype = np.uint8
            else:  # 16-bit
                dtype = np.int16
                
            # Načtení vzorků
            frames = audio_file.readframes(n_frames)
            samples = np.frombuffer(frames, dtype=dtype)
            
        # Extrakce hlavičky délky
        if len(samples) < 32:
            raise ValueError("Soubor je příliš krátký pro extrakci hlavičky")
            
        length_header_bits = ''.join(str(samples[i] & 1) for i in range(32))
        encrypted_data_length_bits = int(length_header_bits, 2)
        
        # Extrakce zašifrovaných dat
        total_bits_to_extract = 32 + encrypted_data_length_bits
        if len(samples) < total_bits_to_extract:
            raise ValueError("Soubor je příliš krátký pro extrakci dat")
            
        encrypted_data_bits = ''.join(str(samples[i] & 1) for i in range(32, total_bits_to_extract))
        
        try:
            encrypted_data_bytes = bits_to_bytes(encrypted_data_bits)
        except ValueError:
            raise ValueError("Nesprávný formát dat v souboru")
            
        # Dešifrování dat
        key = generate_xor_key(password, len(encrypted_data_bytes))
        decrypted_data = xor_cipher(encrypted_data_bytes, key)
        
        # Rozdělení hash a zprávy
        if len(decrypted_data) < 32:
            raise ValueError("Dešifrovaná data jsou příliš krátká")
            
        embedded_hash = decrypted_data[:32]
        extracted_message_bytes = decrypted_data[32:]
        
        # Kontrola integrity
        calculated_hash = hashlib.sha256(extracted_message_bytes).digest()
        if embedded_hash != calculated_hash:
            raise ValueError("Kontrola integrity selhala! Nesprávné heslo nebo poškozená data.")
            
        # Dekódování zprávy
        try:
            message = extracted_message_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Nelze dekódovat extrahovanou zprávu")
            
        return message
        
    except Exception as e:
        raise ValueError(f"Chyba při extrakci zprávy: {str(e)}")

class StegGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Audio Steganography - Nekuda a Kala")
        self.root.geometry("900x900")
        
        # Proměnné pro ukládání cest k souborům
        self.input_wav_path = tk.StringVar()
        self.output_wav_path = tk.StringVar()
        self.extract_input_path = tk.StringVar()
        
        # Proměnné pro kapacitu
        self.total_capacity = tk.StringVar(value="Celková kapacita: -")
        self.used_capacity = tk.StringVar(value="Využitá kapacita: -")
        self.remaining_capacity = tk.StringVar(value="Zbývající kapacita: -")
        self.max_message_length = tk.StringVar(value="Maximální délka zprávy: -")
        
        # Přidání proměnných pro hash
        self.embed_hash = tk.StringVar(value="SHA-256 hash výstupního souboru: -")
        self.extract_hash = tk.StringVar(value="SHA-256 hash vstupního souboru: -")
        
        # Vytvoření hlavního rozložení
        self.create_widgets()
        
    def create_widgets(self):
        # Vytvoření hlavního rámce s posuvníkem
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)
        
        # Přidání vertikálního scrollbaru
        main_scrollbar = tk.Scrollbar(main_frame, orient="vertical")
        main_scrollbar.pack(side="right", fill="y")
        
        # Vytvoření plátna s posuvníkem
        main_canvas = tk.Canvas(main_frame, yscrollcommand=main_scrollbar.set)
        main_canvas.pack(side="left", fill="both", expand=True)
        main_scrollbar.config(command=main_canvas.yview)
        
        # Vytvoření rámce uvnitř plátna pro obsah
        content_frame = tk.Frame(main_canvas)
        canvas_window = main_canvas.create_window((0, 0), window=content_frame, anchor="nw")
        
        # Nastavení posuvníku při změně velikosti okna
        def configure_canvas(event):
            main_canvas.configure(scrollregion=main_canvas.bbox("all"))
            main_canvas.itemconfig(canvas_window, width=event.width)
        
        main_canvas.bind("<Configure>", configure_canvas)
        content_frame.bind("<Configure>", lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all")))
        
        # Nastavení scrollování myší
        def _on_mousewheel(event):
            main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        main_canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Hlavní rámečky pro embed a extract sekce
        style = ttk.Style()
        style.configure('Embed.TLabelframe', background='#f0f8ff')
        style.configure('Embed.TLabelframe.Label', background='#f0f8ff')
        style.configure('Extract.TLabelframe', background='#fff0f5')
        style.configure('Extract.TLabelframe.Label', background='#fff0f5')
        
        # Embed sekce
        embed_frame = ttk.LabelFrame(content_frame, text="Schovej Message", padding="10", style='Embed.TLabelframe')
        embed_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Hlavní kontejner pro embed sekci
        embed_container = tk.Frame(embed_frame, bg='#f0f8ff')
        embed_container.pack(fill="both", expand=True)
        
        # Extract sekce
        extract_frame = ttk.LabelFrame(content_frame, text="Extrahuj Message", padding="10", style='Extract.TLabelframe')
        extract_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Hlavní kontejner pro extract sekci
        extract_container = tk.Frame(extract_frame, bg='#fff0f5')
        extract_container.pack(fill="both", expand=True)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.pack(side="bottom", fill="x", padx=10, pady=5)
        
        # Embed sekce - widgety
        ttk.Button(embed_container, text="Vyber WAV soubor, do kterého chceš zprávu vložit", 
                  command=self.select_input_embed).pack(fill="x", pady=2)
        
        file_label = tk.Label(embed_container, text="Vybraný soubor:", bg='#f0f8ff', anchor='w')
        file_label.pack(fill="x", pady=2)
        
        path_label = tk.Label(embed_container, textvariable=self.input_wav_path, 
                            wraplength=400, bg='#f0f8ff', anchor='w')
        path_label.pack(fill="x", pady=2)
        
        # Informace o kapacitě
        capacity_frame = tk.Frame(embed_container, bg='#f0f8ff')
        capacity_frame.pack(fill="x", pady=5)
        
        tk.Label(capacity_frame, textvariable=self.total_capacity, bg='#f0f8ff', anchor='w').pack(fill="x")
        tk.Label(capacity_frame, textvariable=self.used_capacity, bg='#f0f8ff', anchor='w').pack(fill="x")
        tk.Label(capacity_frame, textvariable=self.remaining_capacity, bg='#f0f8ff', anchor='w').pack(fill="x")
        tk.Label(capacity_frame, textvariable=self.max_message_length, bg='#f0f8ff', anchor='w').pack(fill="x")
        
        tk.Label(embed_container, text="Výstupní soubor:", bg='#f0f8ff', anchor='w').pack(fill="x", pady=2)
        tk.Label(embed_container, textvariable=self.output_wav_path, 
                wraplength=400, bg='#f0f8ff', anchor='w').pack(fill="x", pady=2)
        
        tk.Label(embed_container, text="Tajná zpráva:", bg='#f0f8ff', anchor='w').pack(fill="x", pady=2)
        self.message_text = tk.Text(embed_container, height=5)
        self.message_text.pack(fill="x", pady=2)
        self.message_text.configure(bg='white')  # Zachováme bílé pozadí pro text
        
        # Přidání vazby na změnu textu pro aktualizaci kapacity
        self.message_text.bind('<KeyRelease>', self.update_capacity_info)
        
        tk.Label(embed_container, text="Heslo:", bg='#f0f8ff', anchor='w').pack(fill="x", pady=2)
        self.password_entry = ttk.Entry(embed_container, show="*")
        self.password_entry.pack(fill="x", pady=2)
        
        # Přidání vazby na změnu hesla pro aktualizaci kapacity
        self.password_entry.bind('<KeyRelease>', self.update_capacity_info)
        
        # Přidání tlačítka pro zobrazení detailů embedování
        ttk.Button(embed_container, text="Zobrazit detaily procesu schování zprávy", 
                  command=self.show_embed_details).pack(fill="x", pady=2)
        
        self.embed_button = ttk.Button(embed_container, text="Schovej zprávu", 
                                     state="disabled", command=self.handle_embed)
        self.embed_button.pack(fill="x", pady=5)
        
        # Přidání hashe do embed sekce (před status bar)
        hash_label_embed = tk.Label(embed_container, textvariable=self.embed_hash, 
                                  bg='#f0f8ff', anchor='w', wraplength=800)
        hash_label_embed.pack(fill="x", pady=5)
        
        # Extract sekce - widgety
        ttk.Button(extract_container, text="Vyber wav soubor, ze kterého chceš tajnou zprávu vyextrahovat", 
                  command=self.select_input_extract).pack(fill="x", pady=2)
        
        tk.Label(extract_container, textvariable=self.extract_input_path, 
                wraplength=400, bg='#fff0f5', anchor='w').pack(fill="x", pady=2)
        
        tk.Label(extract_container, text="Heslo:", bg='#fff0f5', anchor='w').pack(fill="x", pady=2)
        self.extract_password_entry = ttk.Entry(extract_container, show="*")
        self.extract_password_entry.pack(fill="x", pady=2)
        
        # Přidání tlačítka pro zobrazení detailů extrakce
        ttk.Button(extract_container, text="Zobrazit detaily procesu extrakce zprávy", 
                  command=self.show_extract_details).pack(fill="x", pady=2)
        
        self.extract_button = ttk.Button(extract_container, text="Extrahuj zprávu", 
                                       state="disabled", command=self.handle_extract)
        self.extract_button.pack(fill="x", pady=5)
        
        # Přidání hashe do extract sekce (před status bar)
        hash_label_extract = tk.Label(extract_container, textvariable=self.extract_hash, 
                                    bg='#fff0f5', anchor='w', wraplength=800)
        hash_label_extract.pack(fill="x", pady=5)
        
        tk.Label(extract_container, text="Extrahovaná zpráva:", bg='#fff0f5', anchor='w').pack(fill="x", pady=2)
        self.extracted_message_text = tk.Text(extract_container, height=5)
        self.extracted_message_text.pack(fill="x", pady=2)
        self.extracted_message_text.configure(bg='white', state="disabled")  # Zachováme bílé pozadí pro text
        
    def calculate_capacity(self, input_path):
        """Vypočítá kapacitu audio souboru pro ukrytí zprávy"""
        try:
            with wave.open(input_path, 'rb') as audio_file:
                n_frames = audio_file.getnframes()
                n_channels = audio_file.getnchannels()
                total_samples = n_frames * n_channels
                
                # Celková kapacita v bitech (každý vzorek může nést 1 bit)
                total_bits = total_samples
                
                # Odečteme 32 bitů pro hlavičku délky
                available_bits = total_bits - 32
                
                # Kapacita v bajtech (každý bajt = 8 bitů)
                available_bytes = available_bits // 8
                
                # Odečteme 32 bajtů pro hash
                available_bytes -= 32
                
                return {
                    'total_bits': total_bits,
                    'available_bits': available_bits,
                    'available_bytes': available_bytes
                }
        except Exception as e:
            raise ValueError(f"Nelze vypočítat kapacitu: {str(e)}")
            
    def update_capacity_info(self, event=None):
        """Aktualizuje informace o kapacitě v GUI"""
        if not self.input_wav_path.get():
            return
            
        try:
            # Výpočet celkové kapacity
            capacity = self.calculate_capacity(self.input_wav_path.get())
            
            # Aktualizace celkové kapacity
            self.total_capacity.set(f"Celková kapacita: {capacity['total_bits']} bitů ({capacity['total_bits']//8} bajtů, ~{capacity['total_bits']//8} znaků)")
            
            # Pokud je vyplněna zpráva a heslo, vypočítáme využitou kapacitu
            message = self.message_text.get("1.0", "end-1c").strip()
            password = self.password_entry.get()
            
            if message and password:
                # Výpočet délky zašifrovaných dat
                message_bytes = message.encode('utf-8')
                hash_bytes = hashlib.sha256(message_bytes).digest()
                data_to_encrypt = hash_bytes + message_bytes
                key = generate_xor_key(password, len(data_to_encrypt))
                encrypted_data = xor_cipher(data_to_encrypt, key)
                
                # Výpočet využitých bitů (32 bitů pro hlavičku + zašifrovaná data)
                used_bits = 32 + (len(encrypted_data) * 8)
                
                # Aktualizace informací o využití
                self.used_capacity.set(f"Využitá kapacita: {used_bits} bitů ({used_bits//8} bajtů, {len(message)} znaků)")
                self.remaining_capacity.set(f"Zbývající kapacita: {capacity['total_bits'] - used_bits} bitů ({(capacity['total_bits'] - used_bits)//8} bajtů, ~{(capacity['total_bits'] - used_bits)//8} znaků)")
                
                # Výpočet maximální délky zprávy
                max_message_bytes = capacity['available_bytes']
                self.max_message_length.set(f"Maximální délka zprávy: ~{max_message_bytes} znaků")
            else:
                # Reset informací o využití
                self.used_capacity.set("Využitá kapacita: -")
                self.remaining_capacity.set("Zbývající kapacita: -")
                self.max_message_length.set("Maximální délka zprávy: -")
                
        except Exception as e:
            self.status_var.set(f"Chyba při výpočtu kapacity: {str(e)}")
            
    def select_input_embed(self):
        """Otevře dialog pro výběr vstupního WAV souboru pro embedování"""
        filename = filedialog.askopenfilename(
            filetypes=[("WAV files", "*.wav")],
            title="Select Input WAV File"
        )
        if filename:
            self.input_wav_path.set(filename)
            # Automaticky vytvoří název výstupního souboru
            base_path = os.path.splitext(filename)[0]  # Získá cestu bez přípony
            output_filename = f"{base_path}_hidden_msg.wav"
            self.output_wav_path.set(output_filename)
            self.check_embed_button_state()
            # Aktualizace informací o kapacitě
            self.update_capacity_info()
            
    def select_input_extract(self):
        """Otevře dialog pro výběr vstupního WAV souboru pro extrakci"""
        filename = filedialog.askopenfilename(
            filetypes=[("WAV files", "*.wav")],
            title="Vyber wav soubor, ze kterého chceš tajnou zprávu vyextrahovat"
        )
        if filename:
            self.extract_input_path.set(filename)
            # Výpočet a zobrazení hashe vstupního souboru
            input_hash = self.calculate_file_hash(filename)
            self.extract_hash.set(f"SHA-256 hash vstupního souboru:\n{input_hash}")
            self.check_extract_button_state()
            
    def check_embed_button_state(self):
        """Kontroluje, zda jsou všechny potřebné vstupy pro embedování vyplněny"""
        if (self.input_wav_path.get() and 
            self.output_wav_path.get() and 
            self.message_text.get("1.0", "end-1c").strip() and 
            self.password_entry.get()):
            self.embed_button.config(state="normal")
        else:
            self.embed_button.config(state="disabled")
            
    def check_extract_button_state(self):
        """Kontroluje, zda jsou všechny potřebné vstupy pro extrakci vyplněny"""
        if (self.extract_input_path.get() and 
            self.extract_password_entry.get()):
            self.extract_button.config(state="normal")
        else:
            self.extract_button.config(state="disabled")
            
    def handle_embed(self):
        """Obsluha tlačítka pro embedování zprávy"""
        try:
            # Získání vstupů z GUI
            input_path = self.input_wav_path.get()
            output_path = self.output_wav_path.get()
            message = self.message_text.get("1.0", "end-1c").strip()
            password = self.password_entry.get()
            
            # Validace vstupů
            if not all([input_path, output_path, message, password]):
                messagebox.showerror("Chyba", "Všechna pole musí být vyplněna")
                return
                
            # Aktualizace stavu
            self.status_var.set("Vkládání zprávy...")
            self.root.update()
            
            # Vložení zprávy
            embed(input_path, output_path, message, password)
            
            # Výpočet a zobrazení hashe výstupního souboru
            output_hash = self.calculate_file_hash(output_path)
            self.embed_hash.set(f"SHA-256 hash výstupního souboru:\n{output_hash}")
            
            # Úspěch
            self.status_var.set("Zpráva byla úspěšně vložena")
            messagebox.showinfo("Úspěch", "Zpráva byla úspěšně vložena do audio souboru")
            
        except Exception as e:
            self.status_var.set("Chyba při vkládání zprávy")
            self.embed_hash.set("SHA-256 hash výstupního souboru: -")
            messagebox.showerror("Chyba", str(e))
            
    def handle_extract(self):
        """Obsluha tlačítka pro extrakci zprávy"""
        try:
            # Získání vstupů z GUI
            input_path = self.extract_input_path.get()
            password = self.extract_password_entry.get()
            
            # Validace vstupů
            if not all([input_path, password]):
                messagebox.showerror("Chyba", "Všechna pole musí být vyplněna")
                return
                
            # Aktualizace stavu
            self.status_var.set("Extrahování zprávy...")
            self.root.update()
            
            # Extrakce zprávy
            message = extract(input_path, password)
            
            # Zobrazení výsledku
            self.extracted_message_text.config(state="normal")
            self.extracted_message_text.delete("1.0", "end")
            self.extracted_message_text.insert("1.0", message)
            self.extracted_message_text.config(state="disabled")
            
            # Úspěch
            self.status_var.set("Zpráva byla úspěšně extrahována")
            messagebox.showinfo("Úspěch", "Zpráva byla úspěšně extrahována")
            
        except Exception as e:
            self.status_var.set("Chyba při extrakci zprávy")
            self.extracted_message_text.config(state="normal")
            self.extracted_message_text.delete("1.0", "end")
            self.extracted_message_text.config(state="disabled")
            messagebox.showerror("Chyba", str(e))

    def show_embed_details(self):
        """Zobrazí okno s detaily procesu embedování"""
        try:
            message = self.message_text.get("1.0", "end-1c").strip()
            password = self.password_entry.get()
            
            if not message or not password:
                messagebox.showerror("Chyba", "Zpráva a heslo musí být vyplněny")
                return
                
            # Vytvoření nového okna
            details_window = tk.Toplevel(self.root)
            details_window.title("Detaily embedování")
            details_window.geometry("800x600")
            
            # Vytvoření textového pole s posuvníkem
            text_frame = ttk.Frame(details_window)
            text_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            scrollbar = ttk.Scrollbar(text_frame)
            scrollbar.pack(side="right", fill="y")
            
            details_text = tk.Text(text_frame, wrap="word", yscrollcommand=scrollbar.set)
            details_text.pack(fill="both", expand=True)
            scrollbar.config(command=details_text.yview)
            
            # Získání a zobrazení detailů
            message_bytes = message.encode('utf-8')
            hash_bytes = hashlib.sha256(message_bytes).digest()
            data_to_encrypt = hash_bytes + message_bytes
            key = generate_xor_key(password, len(data_to_encrypt))
            encrypted_data = xor_cipher(data_to_encrypt, key)
            
            # Vytvoření tagů pro formátování textu
            details_text.tag_configure("bold", font=("TkDefaultFont", 10, "bold"))
            details_text.tag_configure("hash_color", foreground="blue")
            details_text.tag_configure("message_color", foreground="green")
            
            # Zobrazení detailů
            details_text.insert("end", "=== Detaily procesu embedování ===\n\n")
            
            details_text.insert("end", "1. Původní zpráva:\n", "bold")
            details_text.insert("end", f"Text: {message}\n")
            details_text.insert("end", f"Binárně: {text_to_bits(message)}\n\n")
            
            details_text.insert("end", "2. Hash zprávy (SHA-256):\n", "bold")
            details_text.insert("end", f"Hexadecimálně: {hash_bytes.hex()}\n")
            details_text.insert("end", f"Binárně: {bytes_to_bits(hash_bytes)}\n\n")
            
            details_text.insert("end", "3. Data k zašifrování (hash + zpráva):\n", "bold")
            hash_bits = bytes_to_bits(hash_bytes)
            message_bits = bytes_to_bits(message_bytes)
            details_text.insert("end", "Binárně (rozděleno na části):\n")
            details_text.insert("end", "HASH (256 bitů):   ", "bold")
            details_text.insert("end", f"{hash_bits}\n", "hash_color")
            details_text.insert("end", "ZPRÁVA:           ", "bold")
            details_text.insert("end", f"{message_bits}\n", "message_color")
            details_text.insert("end", "SPOJENO:\n")
            details_text.insert("end", f"{bytes_to_bits(data_to_encrypt)}\n\n")
            
            details_text.insert("end", "4. Generovaný klíč:\n", "bold")
            details_text.insert("end", f"Binárně: {bytes_to_bits(key)}\n\n")
            
            details_text.insert("end", "5. Zašifrovaná data (XOR):\n", "bold")
            details_text.insert("end", f"Binárně: {bytes_to_bits(encrypted_data)}\n\n")
            
            details_text.insert("end", "6. Finální payload (32-bit délka + zašifrovaná data):\n", "bold")
            length_header = format(len(encrypted_data) * 8, '032b')
            payload_bits = length_header + bytes_to_bits(encrypted_data)
            details_text.insert("end", f"Binárně: {payload_bits}\n")
            
            # Přidání vysvětlivek
            details_text.insert("end", "\nVysvětlivky:\n", "bold")
            details_text.insert("end", "Modrá: ", "bold")
            details_text.insert("end", "SHA-256 hash (vždy 256 bitů)\n", "hash_color")
            details_text.insert("end", "Zelená: ", "bold")
            details_text.insert("end", "Původní zpráva v binární podobě\n", "message_color")
            
            # Nastavení textového pole na read-only
            details_text.config(state="disabled")
            
        except Exception as e:
            messagebox.showerror("Chyba", f"Nelze zobrazit detaily: {str(e)}")
            
    def show_extract_details(self):
        """Zobrazí okno s detaily procesu extrakce"""
        try:
            input_path = self.extract_input_path.get()
            password = self.extract_password_entry.get()
            
            if not input_path or not password:
                messagebox.showerror("Chyba", "Vstupní soubor a heslo musí být vyplněny")
                return
                
            # Vytvoření nového okna
            details_window = tk.Toplevel(self.root)
            details_window.title("Detaily extrakce")
            details_window.geometry("800x600")
            
            # Vytvoření textového pole s posuvníkem
            text_frame = ttk.Frame(details_window)
            text_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            scrollbar = ttk.Scrollbar(text_frame)
            scrollbar.pack(side="right", fill="y")
            
            details_text = tk.Text(text_frame, wrap="word", yscrollcommand=scrollbar.set)
            details_text.pack(fill="both", expand=True)
            scrollbar.config(command=details_text.yview)
            
            # Načtení WAV souboru a extrakce dat
            with wave.open(input_path, 'rb') as audio_file:
                n_frames = audio_file.getnframes()
                samp_width = audio_file.getsampwidth()
                frames = audio_file.readframes(n_frames)
                
                if samp_width == 1:
                    samples = np.frombuffer(frames, dtype=np.uint8)
                else:
                    samples = np.frombuffer(frames, dtype=np.int16)
                    
            # Extrakce hlavičky délky
            length_header_bits = ''.join(str(samples[i] & 1) for i in range(32))
            encrypted_data_length_bits = int(length_header_bits, 2)
            
            # Extrakce zašifrovaných dat
            total_bits_to_extract = 32 + encrypted_data_length_bits
            encrypted_data_bits = ''.join(str(samples[i] & 1) for i in range(32, total_bits_to_extract))
            encrypted_data_bytes = bits_to_bytes(encrypted_data_bits)
            
            # Dešifrování
            key = generate_xor_key(password, len(encrypted_data_bytes))
            decrypted_data = xor_cipher(encrypted_data_bytes, key)
            
            # Rozdělení hash a zprávy
            embedded_hash = decrypted_data[:32]
            extracted_message_bytes = decrypted_data[32:]
            
            # Zobrazení detailů
            details_text.insert("end", "=== Detaily procesu extrakce ===\n\n")
            
            details_text.insert("end", "1. Extrahovaná hlavička délky:\n")
            details_text.insert("end", f"Binárně: {length_header_bits}\n")
            details_text.insert("end", f"Desítkově: {encrypted_data_length_bits}\n\n")
            
            details_text.insert("end", "2. Extrahovaná zašifrovaná data:\n")
            details_text.insert("end", f"Binárně: {encrypted_data_bits}\n\n")
            
            details_text.insert("end", "3. Generovaný klíč:\n")
            details_text.insert("end", f"Binárně: {bytes_to_bits(key)}\n\n")
            
            details_text.insert("end", "4. Dešifrovaná data:\n")
            details_text.insert("end", f"Binárně: {bytes_to_bits(decrypted_data)}\n\n")
            
            details_text.insert("end", "5. Extrahovaný hash:\n")
            details_text.insert("end", f"Hexadecimálně: {embedded_hash.hex()}\n")
            details_text.insert("end", f"Binárně: {bytes_to_bits(embedded_hash)}\n\n")
            
            details_text.insert("end", "6. Extrahovaná zpráva:\n")
            try:
                message = extracted_message_bytes.decode('utf-8')
                details_text.insert("end", f"Text: {message}\n")
                details_text.insert("end", f"Binárně: {bytes_to_bits(extracted_message_bytes)}\n")
            except UnicodeDecodeError:
                details_text.insert("end", "Nelze dekódovat zprávu (možná špatné heslo)\n")
            
            # Nastavení textového pole na read-only
            details_text.config(state="disabled")
            
        except Exception as e:
            messagebox.showerror("Chyba", f"Nelze zobrazit detaily: {str(e)}")

    def calculate_file_hash(self, file_path):
        """Vypočítá SHA-256 hash souboru"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Čtení souboru po blocích pro efektivitu
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return f"Chyba při výpočtu hashe: {str(e)}"

if __name__ == "__main__":
    root = tk.Tk()
    app = StegGUI(root)
    root.mainloop() 
