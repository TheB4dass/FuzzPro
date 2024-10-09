"""
Copyright (C) [2024] [TheB4dass]
Este programa es software libre; puedes redistribuirlo y/o modificarlo bajo los términos
de la GNU General Public License como se publica por la Free Software Foundation; ya
sea la versión 2 de la Licencia, o (a tu elección) cualquier versión posterior.
"""

import requests
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import RequestException
import threading
import webview

class FuzzingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FuzzPro")
        self.root.config(bg='black')
        self.url_var = tk.StringVar()
        self.timeout_var = tk.DoubleVar(value=2.0)
        self.parallel_var = tk.IntVar(value=5)
        self.wordlist_file = None
        self.results = []
        self.stop_fuzzing = False
        self.selected_extensions = []
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="FuzzPro", font=("Arial", 18), fg='#00ff00', bg='black').place(x=20, y=10)
        left_frame = tk.Frame(self.root, bg='black')
        left_frame.pack(side=tk.LEFT, padx=20, pady=20)
        tk.Label(left_frame, text="Selecciona extensiones:", fg='#00ff00', bg='black').pack(pady=5)

        extensions = ['.php', '.txt', '.ascp', '.asp', '.ptm', '.phar', '.js', '.xml', '.html', '.css', '.json', '.yaml', '.sql', '.env', '.bat', '.pl', '.rb', '.cgi', '.bin']
        for ext in extensions:
            var = tk.BooleanVar()
            checkbox = tk.Checkbutton(left_frame, text=ext, variable=var, fg='#00ff00', bg='black', command=lambda e=ext, v=var: self.toggle_extension(e, v))
            checkbox.pack(anchor=tk.W)

        right_frame = tk.Frame(self.root, bg='black')
        right_frame.pack(side=tk.LEFT, padx=20, pady=20)
        tk.Label(right_frame, text="URL:", fg='#00ff00', bg='black').pack(pady=5)
        self.url_entry = tk.Entry(right_frame, textvariable=self.url_var, width=50, bg='black', fg='#00ff00', insertbackground='#00ff00')
        self.url_entry.pack(padx=10, pady=5)
        self.url_entry.focus()

        self.wordlist_button = tk.Button(right_frame, text="Seleccionar Wordlist", command=self.select_wordlist, bg='black', fg='#00ff00')
        self.wordlist_button.pack(pady=5)

        self.wordlist_label = tk.Label(right_frame, text="Wordlist: Ninguno seleccionado", fg='#00ff00', bg='black')
        self.wordlist_label.pack(pady=5)

        tk.Label(right_frame, text="Timeout (segundos):", fg='#00ff00', bg='black').pack(pady=5)
        self.timeout_entry = tk.Entry(right_frame, textvariable=self.timeout_var, width=10, bg='black', fg='#00ff00', insertbackground='#00ff00')
        self.timeout_entry.pack(pady=5)

        tk.Label(right_frame, text="Número de hilos paralelos:", fg='#00ff00', bg='black').pack(pady=5)
        self.parallel_entry = tk.Entry(right_frame, textvariable=self.parallel_var, width=10, bg='black', fg='#00ff00', insertbackground='#00ff00')
        self.parallel_entry.pack(pady=5)

        self.start_button = tk.Button(right_frame, text="Iniciar Fuzzing", command=self.start_fuzzing_thread, bg='black', fg='#00ff00')
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(right_frame, text="Detener Fuzzing", command=self.stop_fuzzing_process, bg='red', fg='white')
        self.stop_button.pack(pady=10)

        tk.Label(right_frame, text="Progreso:", fg='#00ff00', bg='black').pack(pady=5)
        self.progress_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, width=80, height=5, bg='black', fg='#00ff00')
        self.progress_text.pack(padx=10, pady=5)

        tk.Label(right_frame, text="URLs encontradas:", fg='#00ff00', bg='black').pack(pady=10)
        
        url_frame = tk.Frame(right_frame, bg='black')
        url_frame.pack(padx=10, pady=10)

        self.url_list = tk.Listbox(url_frame, width=80, height=5, bg='black', fg='#00ff00')
        self.url_list.pack(side=tk.LEFT, fill=tk.BOTH)

        self.scrollbar = tk.Scrollbar(url_frame, orient=tk.VERTICAL, command=self.url_list.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.url_list.config(yscrollcommand=self.scrollbar.set)
        self.view_button = tk.Button(right_frame, text="Ver contenido", command=self.view_content, bg='black', fg='#00ff00')
        self.view_button.pack(pady=10)

        tk.Label(self.root, text="Created by TheB4dass", font=("Arial", 12), fg='#00ff00', bg='black').pack(side=tk.BOTTOM)

    def toggle_extension(self, extension, var):
        if var.get():
            self.selected_extensions.append(extension)
        else:
            self.selected_extensions.remove(extension)

    def select_wordlist(self):
        self.wordlist_file = filedialog.askopenfilename(title="Seleccionar archivo de Wordlist", filetypes=(("Archivos de texto", "*.txt"),))
        if self.wordlist_file:
            self.wordlist_label.config(text=f"Wordlist: {self.wordlist_file}")

    def start_fuzzing_thread(self):
        threading.Thread(target=self.start_fuzzing, daemon=True).start()

    def start_fuzzing(self):
        url = self.url_var.get()
        if not url:
            messagebox.showerror("Error", "Por favor, ingresa una URL válida.")
            return

        if not self.wordlist_file:
            messagebox.showerror("Error", "Por favor, selecciona un archivo de wordlist.")
            return

        try:
            with open(self.wordlist_file, 'r') as file:
                words = file.read().splitlines()

            self.url_list.delete(0, tk.END)
            self.results.clear()
            self.progress_text.delete(1.0, tk.END)
            self.stop_fuzzing = False

            with ThreadPoolExecutor(max_workers=self.parallel_var.get()) as executor:
                futures = {}
                for word in words:
                    futures[executor.submit(fetch_url, url, word, self.timeout_var.get(), self.selected_extensions)] = word

                for future in as_completed(futures):
                    if self.stop_fuzzing:
                        break

                    url_fuzzed, status_code = future.result()
                    word = futures[future]

                    if url_fuzzed:
                        if 200 <= status_code <= 299:
                            self.url_list.insert(tk.END, f"Respuesta satisfactoria: {url_fuzzed}")
                            self.results.append(url_fuzzed)
                        elif 300 <= status_code <= 399:
                            self.url_list.insert(tk.END, f"Redirección: {url_fuzzed}")
                            self.results.append(url_fuzzed)

                    self.progress_text.insert(tk.END, f"Probando: {word} -> {url_fuzzed or 'Sin respuesta'} ({status_code})\n")
                    self.progress_text.yview(tk.END)

        except FileNotFoundError:
            messagebox.showerror("Error", "No se pudo leer el archivo de wordlist.")

    def stop_fuzzing_process(self):
        self.stop_fuzzing = True

    def view_content(self):
        selected = self.url_list.curselection()
        if not selected:
            messagebox.showwarning("Advertencia", "Por favor, selecciona una URL.")
            return

        url = self.results[selected[0]]
        webview.create_window(f"Contenido de {url}", url, width=1024, height=768, resizable=True)
        webview.start()

def fetch_url(base_url, word, timeout, selected_extensions):
    try:
        urls_to_test = [base_url + word]
        for ext in selected_extensions:
            urls_to_test.append(base_url + word + ext)

        for url in urls_to_test:
            response = requests.get(url, timeout=timeout)
            if response.ok:
                return url, response.status_code

    except RequestException:
        pass

    return None, 404

if __name__ == "__main__":
    root = tk.Tk()
    app = FuzzingApp(root)
    root.geometry("800x600")
    root.mainloop()
