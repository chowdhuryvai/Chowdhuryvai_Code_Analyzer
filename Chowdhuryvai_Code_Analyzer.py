import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import shutil
import threading
import time
from datetime import datetime

class ChowdhuryVaiAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("ChowdhuryVai Code Analyzer")
        self.root.geometry("900x700")
        self.root.configure(bg="#0a0a0a")
        
        # Set hacker theme colors
        self.bg_color = "#0a0a0a"
        self.fg_color = "#00ff00"
        self.accent_color = "#0088ff"
        self.warning_color = "#ff3300"
        
        self.setup_ui()
        
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg=self.bg_color)
        header_frame.pack(fill="x", padx=20, pady=10)
        
        title_label = tk.Label(
            header_frame, 
            text="ChowdhuryVai Code Analyzer", 
            font=("Courier", 24, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        )
        title_label.pack(pady=10)
        
        subtitle_label = tk.Label(
            header_frame, 
            text="Professional Code Analysis Tool", 
            font=("Courier", 12),
            fg=self.accent_color,
            bg=self.bg_color
        )
        subtitle_label.pack()
        
        # Main content frame
        main_frame = tk.Frame(self.root, bg=self.bg_color)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Folder selection
        folder_frame = tk.Frame(main_frame, bg=self.bg_color)
        folder_frame.pack(fill="x", pady=10)
        
        tk.Label(
            folder_frame, 
            text="Select Folder:", 
            font=("Courier", 12, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        ).pack(anchor="w")
        
        folder_select_frame = tk.Frame(folder_frame, bg=self.bg_color)
        folder_select_frame.pack(fill="x", pady=5)
        
        self.folder_path = tk.StringVar()
        self.folder_entry = tk.Entry(
            folder_select_frame, 
            textvariable=self.folder_path,
            font=("Courier", 10),
            width=60,
            bg="#111111",
            fg=self.fg_color,
            insertbackground=self.fg_color
        )
        self.folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        browse_btn = tk.Button(
            folder_select_frame,
            text="Browse",
            command=self.browse_folder,
            font=("Courier", 10, "bold"),
            bg="#111111",
            fg=self.fg_color,
            activebackground="#222222",
            activeforeground=self.fg_color,
            relief="solid",
            bd=1
        )
        browse_btn.pack(side="right")
        
        # Analysis options
        options_frame = tk.Frame(main_frame, bg=self.bg_color)
        options_frame.pack(fill="x", pady=10)
        
        tk.Label(
            options_frame, 
            text="Analysis Options:", 
            font=("Courier", 12, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        ).pack(anchor="w")
        
        options_inner_frame = tk.Frame(options_frame, bg=self.bg_color)
        options_inner_frame.pack(fill="x", pady=5)
        
        self.analyze_php = tk.BooleanVar(value=True)
        self.analyze_html = tk.BooleanVar(value=True)
        self.analyze_css = tk.BooleanVar(value=True)
        self.analyze_js = tk.BooleanVar(value=True)
        
        tk.Checkbutton(
            options_inner_frame,
            text="PHP",
            variable=self.analyze_php,
            font=("Courier", 10),
            fg=self.fg_color,
            bg=self.bg_color,
            selectcolor="#111111",
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(side="left", padx=(0, 20))
        
        tk.Checkbutton(
            options_inner_frame,
            text="HTML",
            variable=self.analyze_html,
            font=("Courier", 10),
            fg=self.fg_color,
            bg=self.bg_color,
            selectcolor="#111111",
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(side="left", padx=(0, 20))
        
        tk.Checkbutton(
            options_inner_frame,
            text="CSS",
            variable=self.analyze_css,
            font=("Courier", 10),
            fg=self.fg_color,
            bg=self.bg_color,
            selectcolor="#111111",
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(side="left", padx=(0, 20))
        
        tk.Checkbutton(
            options_inner_frame,
            text="JavaScript",
            variable=self.analyze_js,
            font=("Courier", 10),
            fg=self.fg_color,
            bg=self.bg_color,
            selectcolor="#111111",
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(side="left")
        
        # Output folder
        output_frame = tk.Frame(main_frame, bg=self.bg_color)
        output_frame.pack(fill="x", pady=10)
        
        tk.Label(
            output_frame, 
            text="Output Folder:", 
            font=("Courier", 12, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        ).pack(anchor="w")
        
        output_select_frame = tk.Frame(output_frame, bg=self.bg_color)
        output_select_frame.pack(fill="x", pady=5)
        
        self.output_path = tk.StringVar(value="analyzed_results")
        self.output_entry = tk.Entry(
            output_select_frame, 
            textvariable=self.output_path,
            font=("Courier", 10),
            width=60,
            bg="#111111",
            fg=self.fg_color,
            insertbackground=self.fg_color
        )
        self.output_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        output_browse_btn = tk.Button(
            output_select_frame,
            text="Browse",
            command=self.browse_output_folder,
            font=("Courier", 10, "bold"),
            bg="#111111",
            fg=self.fg_color,
            activebackground="#222222",
            activeforeground=self.fg_color,
            relief="solid",
            bd=1
        )
        output_browse_btn.pack(side="right")
        
        # Action buttons
        button_frame = tk.Frame(main_frame, bg=self.bg_color)
        button_frame.pack(fill="x", pady=20)
        
        self.analyze_btn = tk.Button(
            button_frame,
            text="Start Analysis",
            command=self.start_analysis,
            font=("Courier", 12, "bold"),
            bg="#111111",
            fg=self.fg_color,
            activebackground="#222222",
            activeforeground=self.fg_color,
            relief="solid",
            bd=1,
            width=15
        )
        self.analyze_btn.pack(side="left", padx=(0, 10))
        
        self.clear_btn = tk.Button(
            button_frame,
            text="Clear Results",
            command=self.clear_results,
            font=("Courier", 12, "bold"),
            bg="#111111",
            fg=self.warning_color,
            activebackground="#222222",
            activeforeground=self.warning_color,
            relief="solid",
            bd=1,
            width=15
        )
        self.clear_btn.pack(side="left")
        
        # Progress bar
        self.progress = ttk.Progressbar(
            main_frame,
            orient="horizontal",
            length=100,
            mode="determinate"
        )
        self.progress.pack(fill="x", pady=10)
        
        # Status label
        self.status_label = tk.Label(
            main_frame,
            text="Ready to analyze...",
            font=("Courier", 10),
            fg=self.fg_color,
            bg=self.bg_color,
            anchor="w"
        )
        self.status_label.pack(fill="x")
        
        # Results area
        results_frame = tk.Frame(main_frame, bg=self.bg_color)
        results_frame.pack(fill="both", expand=True, pady=10)
        
        tk.Label(
            results_frame, 
            text="Analysis Results:", 
            font=("Courier", 12, "bold"),
            fg=self.fg_color,
            bg=self.bg_color
        ).pack(anchor="w")
        
        # Create a text widget with scrollbar for results
        text_frame = tk.Frame(results_frame, bg=self.bg_color)
        text_frame.pack(fill="both", expand=True, pady=5)
        
        self.results_text = tk.Text(
            text_frame,
            wrap="word",
            bg="#111111",
            fg=self.fg_color,
            insertbackground=self.fg_color,
            font=("Courier", 10),
            height=15
        )
        
        scrollbar = tk.Scrollbar(text_frame, orient="vertical", command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scrollbar.set)
        
        self.results_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Footer with branding
        footer_frame = tk.Frame(self.root, bg=self.bg_color)
        footer_frame.pack(fill="x", padx=20, pady=10)
        
        # Contact information
        contact_info = [
            "Telegram ID: https://t.me/darkvaiadmin",
            "Telegram Channel: https://t.me/windowspremiumkey",
            "Hacking/Cracking Website: https://crackyworld.com/"
        ]
        
        for info in contact_info:
            tk.Label(
                footer_frame,
                text=info,
                font=("Courier", 9),
                fg=self.accent_color,
                bg=self.bg_color
            ).pack(anchor="w")
        
        # Copyright
        tk.Label(
            footer_frame,
            text="© 2023 ChowdhuryVai - All Rights Reserved",
            font=("Courier", 9),
            fg=self.fg_color,
            bg=self.bg_color
        ).pack(anchor="e")
        
    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)
            
    def browse_output_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.output_path.set(folder_selected)
            
    def start_analysis(self):
        if not self.folder_path.get():
            messagebox.showerror("Error", "Please select a folder to analyze.")
            return
            
        # Disable button during analysis
        self.analyze_btn.config(state="disabled")
        
        # Start analysis in a separate thread
        analysis_thread = threading.Thread(target=self.perform_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()
        
    def perform_analysis(self):
        try:
            self.update_status("Starting analysis...")
            self.progress["value"] = 10
            
            # Create output directory
            output_dir = self.output_path.get()
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            # Get list of files to analyze
            files_to_analyze = []
            file_types = []
            
            if self.analyze_php.get():
                file_types.append(".php")
            if self.analyze_html.get():
                file_types.append(".html")
            if self.analyze_css.get():
                file_types.append(".css")
            if self.analyze_js.get():
                file_types.append(".js")
                
            for root, dirs, files in os.walk(self.folder_path.get()):
                for file in files:
                    if any(file.endswith(ext) for ext in file_types):
                        files_to_analyze.append(os.path.join(root, file))
                        
            self.update_status(f"Found {len(files_to_analyze)} files to analyze")
            self.progress["value"] = 30
            
            # Analyze files
            analysis_results = []
            total_files = len(files_to_analyze)
            
            for i, file_path in enumerate(files_to_analyze):
                relative_path = os.path.relpath(file_path, self.folder_path.get())
                self.update_status(f"Analyzing: {relative_path}")
                
                # Copy file to output directory
                output_file_path = os.path.join(output_dir, relative_path)
                os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
                shutil.copy2(file_path, output_file_path)
                
                # Analyze file content
                file_info = self.analyze_file(file_path, relative_path)
                analysis_results.append(file_info)
                
                # Update progress
                progress_value = 30 + (i / total_files) * 60
                self.progress["value"] = progress_value
                
            self.progress["value"] = 95
            self.update_status("Generating report...")
            
            # Generate report
            self.generate_report(analysis_results, output_dir)
            
            self.progress["value"] = 100
            self.update_status(f"Analysis complete! Results saved to: {output_dir}")
            
            # Re-enable button
            self.analyze_btn.config(state="normal")
            
        except Exception as e:
            self.update_status(f"Error during analysis: {str(e)}")
            self.analyze_btn.config(state="normal")
            
    def analyze_file(self, file_path, relative_path):
        file_info = {
            "path": relative_path,
            "size": os.path.getsize(file_path),
            "lines": 0,
            "functions": 0,
            "variables": 0,
            "issues": []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                file_info["lines"] = len(content.splitlines())
                
                # Basic analysis based on file type
                if file_path.endswith('.php'):
                    file_info.update(self.analyze_php_content(content))
                elif file_path.endswith('.js'):
                    file_info.update(self.analyze_js_content(content))
                elif file_path.endswith('.html'):
                    file_info.update(self.analyze_html_content(content))
                elif file_path.endswith('.css'):
                    file_info.update(self.analyze_css_content(content))
                    
        except Exception as e:
            file_info["issues"].append(f"Error reading file: {str(e)}")
            
        return file_info
    
    def analyze_php_content(self, content):
        analysis = {"functions": 0, "variables": 0, "issues": []}
        
        # Count functions
        analysis["functions"] = content.count("function ")
        
        # Count variables (simple approach)
        analysis["variables"] = content.count("$") // 2  # Rough estimate
        
        # Check for common issues
        if "eval(" in content:
            analysis["issues"].append("Found eval() function - potential security risk")
        if "base64_decode(" in content:
            analysis["issues"].append("Found base64_decode() - possible obfuscation")
        if "exec(" in content or "system(" in content:
            analysis["issues"].append("Found system execution functions")
            
        return analysis
    
    def analyze_js_content(self, content):
        analysis = {"functions": 0, "variables": 0, "issues": []}
        
        # Count functions
        analysis["functions"] = content.count("function ") + content.count("=>")
        
        # Count variables (simple approach)
        analysis["variables"] = content.count("let ") + content.count("const ") + content.count("var ")
        
        # Check for common issues
        if "eval(" in content:
            analysis["issues"].append("Found eval() function - potential security risk")
        if "document.cookie" in content:
            analysis["issues"].append("Direct cookie manipulation detected")
        if "innerHTML" in content:
            analysis["issues"].append("innerHTML usage - potential XSS vulnerability")
            
        return analysis
    
    def analyze_html_content(self, content):
        analysis = {"functions": 0, "variables": 0, "issues": []}
        
        # Check for common issues
        if "<script>" in content.lower():
            analysis["issues"].append("Inline scripts detected")
        if "onclick=" in content.lower() or "onload=" in content.lower():
            analysis["issues"].append("Inline event handlers detected")
        if "<iframe" in content.lower():
            analysis["issues"].append("IFrame detected - potential security risk")
            
        return analysis
    
    def analyze_css_content(self, content):
        analysis = {"functions": 0, "variables": 0, "issues": []}
        
        # Count CSS rules
        analysis["functions"] = content.count('{')
        
        # Check for common issues
        if "expression(" in content:
            analysis["issues"].append("CSS expressions detected - deprecated and potentially dangerous")
        if "@import" in content:
            analysis["issues"].append("External imports detected")
            
        return analysis
    
    def generate_report(self, analysis_results, output_dir):
        report_path = os.path.join(output_dir, "analysis_report.txt")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("CHOWDHURYVAI CODE ANALYSIS REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Source folder: {self.folder_path.get()}\n")
            f.write(f"Total files analyzed: {len(analysis_results)}\n\n")
            
            total_issues = 0
            for result in analysis_results:
                f.write(f"File: {result['path']}\n")
                f.write(f"  Size: {result['size']} bytes\n")
                f.write(f"  Lines: {result['lines']}\n")
                f.write(f"  Functions: {result['functions']}\n")
                f.write(f"  Variables: {result['variables']}\n")
                
                if result['issues']:
                    f.write(f"  Issues found: {len(result['issues'])}\n")
                    for issue in result['issues']:
                        f.write(f"    - {issue}\n")
                    total_issues += len(result['issues'])
                else:
                    f.write("  No issues found\n")
                f.write("\n")
                
            f.write("=" * 60 + "\n")
            f.write(f"SUMMARY: Found {total_issues} potential issues across {len(analysis_results)} files\n")
            f.write("=" * 60 + "\n")
            
        # Display results in the UI
        self.display_results(analysis_results, total_issues)
        
    def display_results(self, analysis_results, total_issues):
        self.results_text.delete(1.0, tk.END)
        
        self.results_text.insert(tk.END, "ANALYSIS RESULTS\n", "title")
        self.results_text.insert(tk.END, "="*50 + "\n")
        self.results_text.insert(tk.END, f"Files analyzed: {len(analysis_results)}\n")
        self.results_text.insert(tk.END, f"Total issues found: {total_issues}\n\n")
        
        for result in analysis_results:
            self.results_text.insert(tk.END, f"File: {result['path']}\n", "filename")
            self.results_text.insert(tk.END, f"  Lines: {result['lines']} | ")
            self.results_text.insert(tk.END, f"Functions: {result['functions']} | ")
            self.results_text.insert(tk.END, f"Variables: {result['variables']}\n")
            
            if result['issues']:
                self.results_text.insert(tk.END, f"  Issues: {len(result['issues'])}\n", "warning")
                for issue in result['issues']:
                    self.results_text.insert(tk.END, f"    • {issue}\n", "issue")
            else:
                self.results_text.insert(tk.END, "  No issues found\n", "safe")
                
            self.results_text.insert(tk.END, "\n")
            
        # Configure text tags for styling
        self.results_text.tag_configure("title", foreground=self.accent_color, font=("Courier", 12, "bold"))
        self.results_text.tag_configure("filename", foreground=self.fg_color, font=("Courier", 10, "bold"))
        self.results_text.tag_configure("warning", foreground=self.warning_color)
        self.results_text.tag_configure("issue", foreground=self.warning_color)
        self.results_text.tag_configure("safe", foreground=self.fg_color)
        
    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update_idletasks()
        
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.progress["value"] = 0
        self.status_label.config(text="Ready to analyze...")

def main():
    root = tk.Tk()
    app = ChowdhuryVaiAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
