"""
File Operations GUI
A modern graphical user interface for the FileOperations module
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import customtkinter as ctk
from datetime import datetime
from .file_ops import FileOperations

# Set appearance mode and theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class FileMonitorThread(threading.Thread):
    """Thread for file monitoring to avoid UI freezing"""
    def __init__(self, file_ops, path, interval, callback):
        threading.Thread.__init__(self, daemon=True)
        self.file_ops = file_ops
        self.path = path
        self.interval = interval
        self.callback = callback
        self.running = True
    
    def run(self):
        import time
        import os
        
        try:
            if not os.path.exists(self.path):
                self.callback(f"Error: Path '{self.path}' not found")
                return
                
            self.callback(f"Monitoring {self.path} for changes...")
            
            # Store initial state
            if os.path.isdir(self.path):
                file_states = {}
                for root, dirs, files in os.walk(self.path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        try:
                            file_states[full_path] = os.path.getmtime(full_path)
                        except:
                            pass
            else:
                file_states = {self.path: os.path.getmtime(self.path)}
                
            while self.running:
                time.sleep(self.interval)
                changes = []
                
                # Check for changes in existing files
                for filepath, mtime in list(file_states.items()):
                    try:
                        current_mtime = os.path.getmtime(filepath)
                        if current_mtime != mtime:
                            changes.append(('modified', filepath))
                            file_states[filepath] = current_mtime
                    except FileNotFoundError:
                        changes.append(('deleted', filepath))
                        del file_states[filepath]
                
                # Check for new files if monitoring a directory
                if os.path.isdir(self.path):
                    for root, dirs, files in os.walk(self.path):
                        for file in files:
                            full_path = os.path.join(root, file)
                            if full_path not in file_states:
                                try:
                                    file_states[full_path] = os.path.getmtime(full_path)
                                    changes.append(('created', full_path))
                                except:
                                    pass
                
                # Report changes
                if changes:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    for change_type, filepath in changes:
                        self.callback(f"[{timestamp}] {change_type.upper()}: {filepath}")
                        
        except Exception as e:
            self.callback(f"Error in file monitor: {str(e)}")
    
    def stop(self):
        self.running = False


class FileOperationsGUI(ctk.CTk):
    """Main GUI class for File Operations"""
    def __init__(self):
        super().__init__()
        
        # Initialize file operations
        self.file_ops = FileOperations()
        self.monitor_thread = None
        
        # Configure window
        self.title("File Operations Utility")
        self.geometry("900x600")
        self.minsize(800, 500)
        
        # Create main container with tabs
        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.search_tab = self.tab_view.add("Search")
        self.analyze_tab = self.tab_view.add("Analyze")
        self.monitor_tab = self.tab_view.add("Monitor")
        
        # Configure the tabs
        self._setup_search_tab()
        self._setup_analyze_tab()
        self._setup_monitor_tab()
    
    def _setup_search_tab(self):
        """Setup UI for search tab"""
        # Create frames
        input_frame = ctk.CTkFrame(self.search_tab)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        results_frame = ctk.CTkFrame(self.search_tab)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Input frame controls
        ctk.CTkLabel(input_frame, text="Search Pattern:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.search_pattern = ctk.CTkEntry(input_frame, width=200)
        self.search_pattern.grid(row=0, column=1, padx=10, pady=10, sticky="we")
        self.search_pattern.insert(0, "*.txt")
        
        ctk.CTkLabel(input_frame, text="Directory:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        dir_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        dir_frame.grid(row=1, column=1, padx=10, pady=10, sticky="we")
        dir_frame.columnconfigure(0, weight=1)
        
        self.search_dir = ctk.CTkEntry(dir_frame, width=200)
        self.search_dir.grid(row=0, column=0, sticky="we")
        self.search_dir.insert(0, os.getcwd())
        
        browse_btn = ctk.CTkButton(dir_frame, text="Browse", width=70, command=self._browse_search_dir)
        browse_btn.grid(row=0, column=1, padx=(5, 0))
        
        self.recursive_var = tk.BooleanVar(value=False)
        recursive_check = ctk.CTkCheckBox(input_frame, text="Search Recursively", 
                                       variable=self.recursive_var, onvalue=True, offvalue=False)
        recursive_check.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="w")
        
        search_btn = ctk.CTkButton(input_frame, text="Search Files", command=self._perform_search)
        search_btn.grid(row=3, column=0, columnspan=2, padx=10, pady=10)
        
        # Configure grid weights
        input_frame.columnconfigure(1, weight=1)
        
        # Results area
        ctk.CTkLabel(results_frame, text="Search Results:").pack(anchor="w", padx=10, pady=(10, 5))
        
        self.search_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=10)
        self.search_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
    
    def _setup_analyze_tab(self):
        """Setup UI for analyze tab"""
        # Create frames
        input_frame = ctk.CTkFrame(self.analyze_tab)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        results_frame = ctk.CTkFrame(self.analyze_tab)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Input frame controls
        ctk.CTkLabel(input_frame, text="File Path:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        file_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        file_frame.grid(row=0, column=1, padx=10, pady=10, sticky="we")
        file_frame.columnconfigure(0, weight=1)
        
        self.analyze_file = ctk.CTkEntry(file_frame, width=200)
        self.analyze_file.grid(row=0, column=0, sticky="we")
        
        browse_btn = ctk.CTkButton(file_frame, text="Browse", width=70, command=self._browse_analyze_file)
        browse_btn.grid(row=0, column=1, padx=(5, 0))
        
        ctk.CTkLabel(input_frame, text="File Type:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        
        self.file_type_var = tk.StringVar(value="auto")
        file_type_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        file_type_frame.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        
        auto_radio = ctk.CTkRadioButton(file_type_frame, text="Auto Detect", variable=self.file_type_var, value="auto")
        auto_radio.grid(row=0, column=0, padx=(0, 10))
        
        text_radio = ctk.CTkRadioButton(file_type_frame, text="Text", variable=self.file_type_var, value="text")
        text_radio.grid(row=0, column=1, padx=10)
        
        binary_radio = ctk.CTkRadioButton(file_type_frame, text="Binary", variable=self.file_type_var, value="binary")
        binary_radio.grid(row=0, column=2, padx=10)
        
        analyze_btn = ctk.CTkButton(input_frame, text="Analyze File", command=self._perform_analyze)
        analyze_btn.grid(row=2, column=0, columnspan=2, padx=10, pady=10)
        
        # Configure grid weights
        input_frame.columnconfigure(1, weight=1)
        
        # Results area
        ctk.CTkLabel(results_frame, text="Analysis Results:").pack(anchor="w", padx=10, pady=(10, 5))
        
        self.analyze_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=10)
        self.analyze_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
    
    def _setup_monitor_tab(self):
        """Setup UI for monitor tab"""
        # Create frames
        input_frame = ctk.CTkFrame(self.monitor_tab)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        log_frame = ctk.CTkFrame(self.monitor_tab)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Input frame controls
        ctk.CTkLabel(input_frame, text="Path to Monitor:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        path_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        path_frame.grid(row=0, column=1, padx=10, pady=10, sticky="we")
        path_frame.columnconfigure(0, weight=1)
        
        self.monitor_path = ctk.CTkEntry(path_frame, width=200)
        self.monitor_path.grid(row=0, column=0, sticky="we")
        self.monitor_path.insert(0, os.getcwd())
        
        browse_btn = ctk.CTkButton(path_frame, text="Browse", width=70, command=self._browse_monitor_path)
        browse_btn.grid(row=0, column=1, padx=(5, 0))
        
        ctk.CTkLabel(input_frame, text="Check Interval (seconds):").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.interval_var = ctk.CTkSlider(input_frame, from_=0.5, to=10.0, number_of_steps=19)
        self.interval_var.grid(row=1, column=1, padx=10, pady=10, sticky="we")
        self.interval_var.set(1.0)
        
        self.interval_label = ctk.CTkLabel(input_frame, text="1.0")
        self.interval_label.grid(row=1, column=2, padx=(0, 10))
        self.interval_var.configure(command=self._interval_changed)
        
        button_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        button_frame.grid(row=2, column=0, columnspan=3, padx=10, pady=10)
        
        self.start_btn = ctk.CTkButton(button_frame, text="Start Monitoring", command=self._start_monitoring, fg_color="green")
        self.start_btn.grid(row=0, column=0, padx=10)
        
        self.stop_btn = ctk.CTkButton(button_frame, text="Stop Monitoring", command=self._stop_monitoring, fg_color="red")
        self.stop_btn.grid(row=0, column=1, padx=10)
        self.stop_btn.configure(state="disabled")
        
        clear_btn = ctk.CTkButton(button_frame, text="Clear Log", command=self._clear_monitor_log)
        clear_btn.grid(row=0, column=2, padx=10)
        
        # Configure grid weights
        input_frame.columnconfigure(1, weight=1)
        
        # Log area
        ctk.CTkLabel(log_frame, text="Monitoring Log:").pack(anchor="w", padx=10, pady=(10, 5))
        
        self.monitor_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10)
        self.monitor_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
    
    # Button command methods
    def _browse_search_dir(self):
        directory = filedialog.askdirectory(initialdir=self.search_dir.get())
        if directory:
            self.search_dir.delete(0, tk.END)
            self.search_dir.insert(0, directory)
    
    def _browse_analyze_file(self):
        filename = filedialog.askopenfilename(initialdir=os.getcwd())
        if filename:
            self.analyze_file.delete(0, tk.END)
            self.analyze_file.insert(0, filename)
    
    def _browse_monitor_path(self):
        path = filedialog.askdirectory(initialdir=self.monitor_path.get())
        if path:
            self.monitor_path.delete(0, tk.END)
            self.monitor_path.insert(0, path)
    
    def _interval_changed(self, value):
        self.interval_label.configure(text=f"{value:.1f}")
    
    def _perform_search(self):
        """Execute file search and display results"""
        # Clear previous results
        self.search_results.delete(1.0, tk.END)
        
        pattern = self.search_pattern.get()
        directory = self.search_dir.get()
        recursive = self.recursive_var.get()
        
        # Redirect stdout to capture results
        import io
        import sys
        
        old_stdout = sys.stdout
        redirected_output = io.StringIO()
        sys.stdout = redirected_output
        
        # Execute search
        try:
            self.file_ops.search(pattern, directory, recursive)
            self.search_results.insert(tk.END, redirected_output.getvalue())
        except Exception as e:
            self.search_results.insert(tk.END, f"Error: {str(e)}")
        finally:
            sys.stdout = old_stdout
    
    def _perform_analyze(self):
        """Execute file analysis and display results"""
        # Clear previous results
        self.analyze_results.delete(1.0, tk.END)
        
        filepath = self.analyze_file.get()
        file_type = self.file_type_var.get()
        
        if not filepath:
            self.analyze_results.insert(tk.END, "Please select a file to analyze")
            return
        
        # Redirect stdout to capture results
        import io
        import sys
        
        old_stdout = sys.stdout
        redirected_output = io.StringIO()
        sys.stdout = redirected_output
        
        # Execute analysis
        try:
            self.file_ops.analyze(filepath, file_type)
            self.analyze_results.insert(tk.END, redirected_output.getvalue())
        except Exception as e:
            self.analyze_results.insert(tk.END, f"Error: {str(e)}")
        finally:
            sys.stdout = old_stdout
    
    def _start_monitoring(self):
        """Start file monitoring"""
        path = self.monitor_path.get()
        interval = self.interval_var.get()
        
        if not path:
            self.log_monitor_message("Please specify a path to monitor")
            return
        
        # Disable/enable buttons
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        
        # Start monitoring in thread
        self.monitor_thread = FileMonitorThread(
            self.file_ops, 
            path, 
            interval, 
            self.log_monitor_message
        )
        self.monitor_thread.start()
    
    def _stop_monitoring(self):
        """Stop file monitoring"""
        if self.monitor_thread:
            self.monitor_thread.stop()
            self.monitor_thread = None
            
        # Update buttons
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.log_monitor_message("Monitoring stopped")
    
    def _clear_monitor_log(self):
        """Clear the monitor log"""
        self.monitor_log.delete(1.0, tk.END)
    
    def log_monitor_message(self, message):
        """Add a message to the monitor log"""
        self.monitor_log.insert(tk.END, message + "\n")
        self.monitor_log.see(tk.END)  # Scroll to the end
    
    def on_closing(self):
        """Handle window closing"""
        if self.monitor_thread:
            self.monitor_thread.stop()
        self.destroy()


if __name__ == "__main__":
    app = FileOperationsGUI()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()