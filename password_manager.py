import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip
import hashlib

class PasswordManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        self.data_file = "passwords.enc"
        self.master_hash_file = "master.hash"
        self.cipher_suite = None
        self.passwords = {}
        
        # Check if master password exists
        if os.path.exists(self.master_hash_file):
            self.authenticate()
        else:
            self.setup_master_password()
        
        self.create_gui()
        
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def setup_master_password(self):
        """Setup master password for first time use"""
        password = simpledialog.askstring("Setup", "Create a master password:", show='*')
        if not password:
            self.root.destroy()
            return
            
        confirm = simpledialog.askstring("Setup", "Confirm master password:", show='*')
        if password != confirm:
            messagebox.showerror("Error", "Passwords don't match!")
            self.root.destroy()
            return
        
        # Generate salt and hash master password
        salt = os.urandom(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        
        # Save master password hash
        with open(self.master_hash_file, 'wb') as f:
            f.write(salt + password_hash)
        
        # Initialize cipher
        key = self.derive_key(password, salt)
        self.cipher_suite = Fernet(key)
        
        messagebox.showinfo("Success", "Master password created successfully!")
    
    def authenticate(self):
        """Authenticate with master password"""
        password = simpledialog.askstring("Authentication", "Enter master password:", show='*')
        if not password:
            self.root.destroy()
            return
        
        # Read stored hash
        with open(self.master_hash_file, 'rb') as f:
            data = f.read()
            salt = data[:16]
            stored_hash = data[16:]
        
        # Verify password
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        
        if password_hash != stored_hash:
            messagebox.showerror("Error", "Invalid master password!")
            self.root.destroy()
            return
        
        # Initialize cipher
        key = self.derive_key(password, salt)
        self.cipher_suite = Fernet(key)
        
        # Load existing passwords
        self.load_passwords()
    
    def load_passwords(self):
        """Load and decrypt passwords from file"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'rb') as f:
                    encrypted_data = f.read()
                
                if encrypted_data:
                    decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                    self.passwords = json.loads(decrypted_data.decode())
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load passwords: {str(e)}")
    
    def save_passwords(self):
        """Encrypt and save passwords to file"""
        try:
            data = json.dumps(self.passwords).encode()
            encrypted_data = self.cipher_suite.encrypt(data)
            
            with open(self.data_file, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save passwords: {str(e)}")
    
    def create_gui(self):
        """Create the main GUI"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="🔐 Secure Password Manager", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Add new password section
        add_frame = ttk.LabelFrame(main_frame, text="Add New Password", padding="10")
        add_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        add_frame.columnconfigure(1, weight=1)
        
        # Input fields
        ttk.Label(add_frame, text="Website/Service:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.website_entry = ttk.Entry(add_frame, width=30)
        self.website_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Label(add_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.username_entry = ttk.Entry(add_frame, width=30)
        self.username_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        ttk.Label(add_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.password_entry = ttk.Entry(add_frame, width=30, show='*')
        self.password_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        # Buttons
        button_frame = ttk.Frame(add_frame)
        button_frame.grid(row=0, column=2, rowspan=3, padx=(10, 0))
        
        ttk.Button(button_frame, text="Add Password", command=self.add_password).pack(pady=2)
        ttk.Button(button_frame, text="Generate Password", command=self.generate_password).pack(pady=2)
        
        # Search section
        search_frame = ttk.Frame(main_frame)
        search_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        search_frame.columnconfigure(1, weight=1)
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=(0, 10))
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        self.search_entry.bind('<KeyRelease>', self.filter_passwords)
        
        # Password list
        list_frame = ttk.LabelFrame(main_frame, text="Saved Passwords", padding="10")
        list_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Treeview for password list
        columns = ('Website', 'Username')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # Define headings
        self.tree.heading('Website', text='Website/Service')
        self.tree.heading('Username', text='Username')
        
        # Configure column widths
        self.tree.column('Website', width=300)
        self.tree.column('Username', width=300)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Grid treeview and scrollbar
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy Username", command=self.copy_username)
        self.context_menu.add_command(label="Copy Password", command=self.copy_password)
        self.context_menu.add_command(label="Edit", command=self.edit_password)
        self.context_menu.add_command(label="Delete", command=self.delete_password)
        
        self.tree.bind("<Button-3>", self.show_context_menu)  # Right click
        self.tree.bind("<Double-1>", self.copy_password)  # Double click
        
        # Load existing passwords into tree
        self.refresh_password_list()
    
    def add_password(self):
        """Add a new password entry"""
        website = self.website_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not all([website, username, password]):
            messagebox.showerror("Error", "Please fill in all fields!")
            return
        
        # Check if entry already exists
        if website in self.passwords:
            if not messagebox.askyesno("Confirm", f"Entry for {website} already exists. Overwrite?"):
                return
        
        self.passwords[website] = {
            'username': username,
            'password': password
        }
        
        self.save_passwords()
        self.refresh_password_list()
        
        # Clear input fields
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        
        messagebox.showinfo("Success", "Password saved successfully!")
    
    def generate_password(self):
        """Generate a random password"""
        import random
        import string
        
        length = 16
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(random.choice(characters) for _ in range(length))
        
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
    
    def refresh_password_list(self):
        """Refresh the password list in the treeview"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add passwords to tree
        for website, data in sorted(self.passwords.items()):
            self.tree.insert('', tk.END, values=(website, data['username']))
    
    def filter_passwords(self, event=None):
        """Filter passwords based on search term"""
        search_term = self.search_entry.get().lower()
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add filtered passwords
        for website, data in sorted(self.passwords.items()):
            if (search_term in website.lower() or 
                search_term in data['username'].lower()):
                self.tree.insert('', tk.END, values=(website, data['username']))
    
    def show_context_menu(self, event):
        """Show context menu on right click"""
        item = self.tree.selection()[0] if self.tree.selection() else None
        if item:
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_username(self):
        """Copy username to clipboard"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            website = item['values'][0]
            username = self.passwords[website]['username']
            pyperclip.copy(username)
            messagebox.showinfo("Copied", "Username copied to clipboard!")
    
    def copy_password(self, event=None):
        """Copy password to clipboard"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            website = item['values'][0]
            password = self.passwords[website]['password']
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
    
    def edit_password(self):
        """Edit selected password entry"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        website = item['values'][0]
        current_data = self.passwords[website]
        
        # Create edit dialog
        edit_window = tk.Toplevel(self.root)
        edit_window.title(f"Edit - {website}")
        edit_window.geometry("400x200")
        edit_window.transient(self.root)
        edit_window.grab_set()
        
        # Center the window
        edit_window.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        frame = ttk.Frame(edit_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        username_var = tk.StringVar(value=current_data['username'])
        username_entry = ttk.Entry(frame, textvariable=username_var, width=30)
        username_entry.grid(row=0, column=1, pady=5, padx=(10, 0))
        
        ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        password_var = tk.StringVar(value=current_data['password'])
        password_entry = ttk.Entry(frame, textvariable=password_var, width=30, show='*')
        password_entry.grid(row=1, column=1, pady=5, padx=(10, 0))
        
        def save_changes():
            self.passwords[website] = {
                'username': username_var.get(),
                'password': password_var.get()
            }
            self.save_passwords()
            self.refresh_password_list()
            edit_window.destroy()
            messagebox.showinfo("Success", "Password updated successfully!")
        
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="Save", command=save_changes).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=edit_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def delete_password(self):
        """Delete selected password entry"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        website = item['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Delete password for {website}?"):
            del self.passwords[website]
            self.save_passwords()
            self.refresh_password_list()
            messagebox.showinfo("Success", "Password deleted successfully!")
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = PasswordManager()
    app.run()
