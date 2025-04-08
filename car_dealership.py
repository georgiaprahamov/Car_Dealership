import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from datetime import datetime
import hashlib
import os


class LoginWindow:
    def __init__(self, root, db_connection, on_login_success):
        self.root = root
        self.conn = db_connection
        self.cursor = self.conn.cursor()
        self.on_login_success = on_login_success

        # Configure the window
        self.root.title("Car Dealership - Login")
        self.root.geometry("400x500")
        self.root.configure(bg="#f0f0f0")

        # Create login frame
        self.login_frame = ttk.Frame(root, padding=20)
        self.login_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title
        ttk.Label(self.login_frame, text="Car Dealership Management System", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(self.login_frame, text="Login to your account", font=("Arial", 10)).pack(pady=5)

        # Username
        ttk.Label(self.login_frame, text="Username:").pack(anchor=tk.W, pady=(10, 2))
        self.username_var = tk.StringVar()
        ttk.Entry(self.login_frame, textvariable=self.username_var, width=30).pack(fill=tk.X, pady=(0, 10))

        # Password
        ttk.Label(self.login_frame, text="Password:").pack(anchor=tk.W, pady=(0, 2))
        self.password_var = tk.StringVar()
        ttk.Entry(self.login_frame, textvariable=self.password_var, show="*", width=30).pack(fill=tk.X, pady=(0, 10))

        # Login button
        ttk.Button(self.login_frame, text="Login", command=self.login).pack(pady=10)

        # Register button (changed from link to button)
        register_frame = ttk.Frame(self.login_frame)
        register_frame.pack(pady=5)
        ttk.Label(register_frame, text="Don't have an account?").grid(row=0, column=0, padx=5)

        # Create a style for the register button
        style = ttk.Style()
        style.configure("Register.TButton", background="white", foreground="black")

        register_button = ttk.Button(register_frame, text="Register", style="Register.TButton",
                                     command=self.show_register_cmd)
        register_button.grid(row=0, column=1, padx=5)

        # Initialize database
        self.init_database()

    def show_register_cmd(self):
        # Call the show_register method without the event parameter
        self.show_register(None)

    def init_database(self):
        # Create users table if it doesn't exist
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        ''')

        # Check if admin user exists, if not create one
        self.cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if self.cursor.fetchone()[0] == 0:
            # Create admin user with password 'admin'
            hashed_password = self.hash_password('admin')
            self.cursor.execute('''
            INSERT INTO users (username, password, full_name, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            ''', ('admin', hashed_password, 'Administrator', 'admin', datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self.conn.commit()

    def hash_password(self, password):
        # Simple password hashing
        return hashlib.sha256(password.encode()).hexdigest()

    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password!")
            return

        # Hash the password
        hashed_password = self.hash_password(password)

        # Check credentials
        self.cursor.execute("SELECT id, username, full_name, role FROM users WHERE username = ? AND password = ?",
                            (username, hashed_password))
        user = self.cursor.fetchone()

        if user:
            # Login successful
            messagebox.showinfo("Success", f"Welcome, {user[2]}!")
            self.login_frame.destroy()
            self.on_login_success(user)
        else:
            messagebox.showerror("Error", "Invalid username or password!")

    def show_register(self, event):
        # Hide login frame
        self.login_frame.pack_forget()

        # Create register frame
        self.register_frame = ttk.Frame(self.root, padding=20)
        self.register_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title
        ttk.Label(self.register_frame, text="Register New Account", font=("Arial", 14, "bold")).pack(pady=10)

        # Username
        ttk.Label(self.register_frame, text="Username:").pack(anchor=tk.W, pady=(10, 2))
        self.reg_username_var = tk.StringVar()
        ttk.Entry(self.register_frame, textvariable=self.reg_username_var, width=30).pack(fill=tk.X, pady=(0, 10))

        # Full Name
        ttk.Label(self.register_frame, text="Full Name:").pack(anchor=tk.W, pady=(0, 2))
        self.reg_fullname_var = tk.StringVar()
        ttk.Entry(self.register_frame, textvariable=self.reg_fullname_var, width=30).pack(fill=tk.X, pady=(0, 10))

        # Password
        ttk.Label(self.register_frame, text="Password:").pack(anchor=tk.W, pady=(0, 2))
        self.reg_password_var = tk.StringVar()
        ttk.Entry(self.register_frame, textvariable=self.reg_password_var, show="*", width=30).pack(fill=tk.X,
                                                                                                    pady=(0, 10))

        # Confirm Password
        ttk.Label(self.register_frame, text="Confirm Password:").pack(anchor=tk.W, pady=(0, 2))
        self.reg_confirm_var = tk.StringVar()
        ttk.Entry(self.register_frame, textvariable=self.reg_confirm_var, show="*", width=30).pack(fill=tk.X,
                                                                                                   pady=(0, 10))

        # Role
        ttk.Label(self.register_frame, text="Role:").pack(anchor=tk.W, pady=(0, 2))
        self.reg_role_var = tk.StringVar(value="employee")
        role_combo = ttk.Combobox(self.register_frame, textvariable=self.reg_role_var, width=30)
        role_combo['values'] = ('employee', 'manager', 'admin')
        role_combo.pack(fill=tk.X, pady=(0, 10))

        # Buttons
        buttons_frame = ttk.Frame(self.register_frame)
        buttons_frame.pack(pady=10)
        ttk.Button(buttons_frame, text="Register", command=self.register).grid(row=0, column=0, padx=5)
        ttk.Button(buttons_frame, text="Back to Login", command=self.back_to_login).grid(row=0, column=1, padx=5)

    def register(self):
        username = self.reg_username_var.get()
        full_name = self.reg_fullname_var.get()
        password = self.reg_password_var.get()
        confirm = self.reg_confirm_var.get()
        role = self.reg_role_var.get()

        # Validate
        if not username or not full_name or not password or not confirm:
            messagebox.showerror("Error", "All fields are required!")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        # Check if username exists
        self.cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        if self.cursor.fetchone()[0] > 0:
            messagebox.showerror("Error", "Username already exists!")
            return

        # Hash the password
        hashed_password = self.hash_password(password)

        # Insert new user
        try:
            self.cursor.execute('''
            INSERT INTO users (username, password, full_name, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            ''', (username, hashed_password, full_name, role, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self.conn.commit()
            messagebox.showinfo("Success", "Account created successfully! You can now login.")
            self.back_to_login()
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Database error: {e}")

    def back_to_login(self):
        # Hide register frame
        self.register_frame.destroy()

        # Show login frame
        self.login_frame = ttk.Frame(self.root, padding=20)
        self.login_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title
        ttk.Label(self.login_frame, text="Car Dealership Management System", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(self.login_frame, text="Login to your account", font=("Arial", 10)).pack(pady=5)

        # Username
        ttk.Label(self.login_frame, text="Username:").pack(anchor=tk.W, pady=(10, 2))
        self.username_var = tk.StringVar()
        ttk.Entry(self.login_frame, textvariable=self.username_var, width=30).pack(fill=tk.X, pady=(0, 10))

        # Password
        ttk.Label(self.login_frame, text="Password:").pack(anchor=tk.W, pady=(0, 2))
        self.password_var = tk.StringVar()
        ttk.Entry(self.login_frame, textvariable=self.password_var, show="*", width=30).pack(fill=tk.X, pady=(0, 10))

        # Login button
        ttk.Button(self.login_frame, text="Login", command=self.login).pack(pady=10)

        # Register button (changed from link to button)
        register_frame = ttk.Frame(self.login_frame)
        register_frame.pack(pady=5)
        ttk.Label(register_frame, text="Don't have an account?").grid(row=0, column=0, padx=5)

        # Create a style for the register button
        style = ttk.Style()
        style.configure("Register.TButton", background="white", foreground="black")

        register_button = ttk.Button(register_frame, text="Register", style="Register.TButton",
                                     command=self.show_register_cmd)
        register_button.grid(row=0, column=1, padx=5)


class CarDealershipApp:
    def __init__(self, root, user_info):
        self.root = root
        self.user_info = user_info  # (id, username, full_name, role)
        self.root.title(f"Car Dealership Management System - Logged in as {user_info[2]}")
        self.root.geometry("1300x600")
        self.root.configure(bg="#f0f0f0")

        # Initialize database - use the same database file
        self.conn = sqlite3.connect('car_dealer.db')
        self.cursor = self.conn.cursor()
        self.init_database()

        # Create main notebook with tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self.inventory_tab = ttk.Frame(self.notebook)
        self.customers_tab = ttk.Frame(self.notebook)
        self.sales_tab = ttk.Frame(self.notebook)
        self.users_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.inventory_tab, text="Inventory")
        self.notebook.add(self.customers_tab, text="Customers")
        self.notebook.add(self.sales_tab, text="Sales")

        # Only show users tab for admins
        if user_info[3] == 'admin':
            self.notebook.add(self.users_tab, text="Users")

        # Setup each tab
        self.setup_inventory_tab()
        self.setup_customers_tab()
        self.setup_sales_tab()

        if user_info[3] == 'admin':
            self.setup_users_tab()

        # Add status bar
        self.status_bar = ttk.Label(root, text=f"Logged in as: {user_info[2]} | Role: {user_info[3]}", relief=tk.SUNKEN,
                                    anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Add logout button
        self.logout_button = ttk.Button(root, text="Logout", command=self.logout)
        self.logout_button.place(relx=0.95, rely=0.02, anchor=tk.NE)

    def init_database(self):
        # Create tables with correct FOREIGN KEY syntax
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS cars (
            id INTEGER PRIMARY KEY,
            make TEXT NOT NULL,
            model TEXT NOT NULL,
            year INTEGER NOT NULL,
            color TEXT NOT NULL,
            price REAL NOT NULL,
            status TEXT DEFAULT 'Available',
            created_by INTEGER,
            created_at TEXT
        )
        ''')

        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT,
            address TEXT,
            created_by INTEGER,
            created_at TEXT
        )
        ''')

        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY,
            car_id INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            sale_date TEXT NOT NULL,
            sale_price REAL NOT NULL,
            created_by INTEGER,
            created_at TEXT,
            FOREIGN KEY (car_id) REFERENCES cars (id),
            FOREIGN KEY (customer_id) REFERENCES customers (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
        ''')

        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        ''')

        self.conn.commit()

    def setup_inventory_tab(self):
        # Left frame for car list
        left_frame = ttk.Frame(self.inventory_tab)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Search frame
        search_frame = ttk.LabelFrame(left_frame, text="Search")
        search_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=5, pady=5)
        self.search_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.search_var).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(search_frame, text="Search", command=self.search_cars).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(search_frame, text="Clear", command=self.clear_search).grid(row=0, column=3, padx=5, pady=5)

        # Car list
        car_list_frame = ttk.LabelFrame(left_frame, text="Car Inventory")
        car_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Treeview for car list
        columns = ('id', 'make', 'model', 'year', 'color', 'price', 'status', 'created_by')
        self.car_tree = ttk.Treeview(car_list_frame, columns=columns, show='headings')

        # Define headings
        self.car_tree.heading('id', text='ID')
        self.car_tree.heading('make', text='Make')
        self.car_tree.heading('model', text='Model')
        self.car_tree.heading('year', text='Year')
        self.car_tree.heading('color', text='Color')
        self.car_tree.heading('price', text='Price')
        self.car_tree.heading('status', text='Status')
        self.car_tree.heading('created_by', text='Added By')

        # Define columns
        self.car_tree.column('id', width=50)
        self.car_tree.column('make', width=100)
        self.car_tree.column('model', width=100)
        self.car_tree.column('year', width=70)
        self.car_tree.column('color', width=80)
        self.car_tree.column('price', width=100)
        self.car_tree.column('status', width=100)
        self.car_tree.column('created_by', width=100)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(car_list_frame, orient=tk.VERTICAL, command=self.car_tree.yview)
        self.car_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.car_tree.pack(fill=tk.BOTH, expand=True)

        # Bind select event
        self.car_tree.bind('<<TreeviewSelect>>', self.on_car_select)

        # Right frame for car details
        right_frame = ttk.Frame(self.inventory_tab)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=5, pady=5)

        # Car details frame
        car_details_frame = ttk.LabelFrame(right_frame, text="Car Details")
        car_details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Car details form
        ttk.Label(car_details_frame, text="Make:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.make_var = tk.StringVar()
        ttk.Entry(car_details_frame, textvariable=self.make_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(car_details_frame, text="Model:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.model_var = tk.StringVar()
        ttk.Entry(car_details_frame, textvariable=self.model_var).grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(car_details_frame, text="Year:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.year_var = tk.StringVar()
        ttk.Entry(car_details_frame, textvariable=self.year_var).grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(car_details_frame, text="Color:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.color_var = tk.StringVar()
        ttk.Entry(car_details_frame, textvariable=self.color_var).grid(row=3, column=1, padx=5, pady=5)

        ttk.Label(car_details_frame, text="Price:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.price_var = tk.StringVar()
        ttk.Entry(car_details_frame, textvariable=self.price_var).grid(row=4, column=1, padx=5, pady=5)

        ttk.Label(car_details_frame, text="Status:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
        self.status_var = tk.StringVar()
        status_combo = ttk.Combobox(car_details_frame, textvariable=self.status_var)
        status_combo['values'] = ('Available', 'Sold', 'Reserved', 'In Service')
        status_combo.grid(row=5, column=1, padx=5, pady=5)

        # Buttons frame
        buttons_frame = ttk.Frame(car_details_frame)
        buttons_frame.grid(row=6, column=0, columnspan=2, pady=10)

        ttk.Button(buttons_frame, text="Add New", command=self.add_car).grid(row=0, column=0, padx=5)
        ttk.Button(buttons_frame, text="Update", command=self.update_car).grid(row=0, column=1, padx=5)
        ttk.Button(buttons_frame, text="Delete", command=self.delete_car).grid(row=0, column=2, padx=5)
        ttk.Button(buttons_frame, text="Clear", command=self.clear_car_form).grid(row=0, column=3, padx=5)

        # Load initial data
        self.load_cars()

    def setup_customers_tab(self):
        # Left frame for customer list
        left_frame = ttk.Frame(self.customers_tab)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Search frame
        search_frame = ttk.LabelFrame(left_frame, text="Search")
        search_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=5, pady=5)
        self.customer_search_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.customer_search_var).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(search_frame, text="Search", command=self.search_customers).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(search_frame, text="Clear", command=self.clear_customer_search).grid(row=0, column=3, padx=5, pady=5)

        # Customer list
        customer_list_frame = ttk.LabelFrame(left_frame, text="Customer List")
        customer_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Treeview for customer list
        columns = ('id', 'name', 'phone', 'email', 'address', 'created_by')
        self.customer_tree = ttk.Treeview(customer_list_frame, columns=columns, show='headings')

        # Define headings
        self.customer_tree.heading('id', text='ID')
        self.customer_tree.heading('name', text='Name')
        self.customer_tree.heading('phone', text='Phone')
        self.customer_tree.heading('email', text='Email')
        self.customer_tree.heading('address', text='Address')
        self.customer_tree.heading('created_by', text='Added By')

        # Define columns
        self.customer_tree.column('id', width=50)
        self.customer_tree.column('name', width=150)
        self.customer_tree.column('phone', width=120)
        self.customer_tree.column('email', width=150)
        self.customer_tree.column('address', width=200)
        self.customer_tree.column('created_by', width=100)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(customer_list_frame, orient=tk.VERTICAL, command=self.customer_tree.yview)
        self.customer_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.customer_tree.pack(fill=tk.BOTH, expand=True)

        # Bind select event
        self.customer_tree.bind('<<TreeviewSelect>>', self.on_customer_select)

        # Right frame for customer details
        right_frame = ttk.Frame(self.customers_tab)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=5, pady=5)

        # Customer details frame
        customer_details_frame = ttk.LabelFrame(right_frame, text="Customer Details")
        customer_details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Customer details form
        ttk.Label(customer_details_frame, text="Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.customer_name_var = tk.StringVar()
        ttk.Entry(customer_details_frame, textvariable=self.customer_name_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(customer_details_frame, text="Phone:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.customer_phone_var = tk.StringVar()
        ttk.Entry(customer_details_frame, textvariable=self.customer_phone_var).grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(customer_details_frame, text="Email:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.customer_email_var = tk.StringVar()
        ttk.Entry(customer_details_frame, textvariable=self.customer_email_var).grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(customer_details_frame, text="Address:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.customer_address_var = tk.StringVar()
        ttk.Entry(customer_details_frame, textvariable=self.customer_address_var).grid(row=3, column=1, padx=5, pady=5)

        # Buttons frame
        buttons_frame = ttk.Frame(customer_details_frame)
        buttons_frame.grid(row=4, column=0, columnspan=2, pady=10)

        ttk.Button(buttons_frame, text="Add New", command=self.add_customer).grid(row=0, column=0, padx=5)
        ttk.Button(buttons_frame, text="Update", command=self.update_customer).grid(row=0, column=1, padx=5)
        ttk.Button(buttons_frame, text="Delete", command=self.delete_customer).grid(row=0, column=2, padx=5)
        ttk.Button(buttons_frame, text="Clear", command=self.clear_customer_form).grid(row=0, column=3, padx=5)

        # Load initial data
        self.load_customers()

    def setup_sales_tab(self):
        # Top frame for sales list
        top_frame = ttk.Frame(self.sales_tab)
        top_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Sales list
        sales_list_frame = ttk.LabelFrame(top_frame, text="Sales Records")
        sales_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Treeview for sales list
        columns = ('id', 'car', 'customer', 'date', 'price', 'created_by')
        self.sales_tree = ttk.Treeview(sales_list_frame, columns=columns, show='headings')

        # Define headings
        self.sales_tree.heading('id', text='ID')
        self.sales_tree.heading('car', text='Car')
        self.sales_tree.heading('customer', text='Customer')
        self.sales_tree.heading('date', text='Sale Date')
        self.sales_tree.heading('price', text='Sale Price')
        self.sales_tree.heading('created_by', text='Recorded By')

        # Define columns
        self.sales_tree.column('id', width=50)
        self.sales_tree.column('car', width=200)
        self.sales_tree.column('customer', width=200)
        self.sales_tree.column('date', width=100)
        self.sales_tree.column('price', width=100)
        self.sales_tree.column('created_by', width=100)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(sales_list_frame, orient=tk.VERTICAL, command=self.sales_tree.yview)
        self.sales_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.sales_tree.pack(fill=tk.BOTH, expand=True)

        # Bottom frame for new sale
        bottom_frame = ttk.Frame(self.sales_tab)
        bottom_frame.pack(fill=tk.X, padx=5, pady=5)

        # New sale frame
        new_sale_frame = ttk.LabelFrame(bottom_frame, text="New Sale")
        new_sale_frame.pack(fill=tk.X, padx=5, pady=5)

        # New sale form
        ttk.Label(new_sale_frame, text="Select Car:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.sale_car_var = tk.StringVar()
        self.car_combo = ttk.Combobox(new_sale_frame, textvariable=self.sale_car_var, width=30)
        self.car_combo.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(new_sale_frame, text="Select Customer:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.sale_customer_var = tk.StringVar()
        self.customer_combo = ttk.Combobox(new_sale_frame, textvariable=self.sale_customer_var, width=30)
        self.customer_combo.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(new_sale_frame, text="Sale Price:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.sale_price_var = tk.StringVar()
        ttk.Entry(new_sale_frame, textvariable=self.sale_price_var).grid(row=2, column=1, padx=5, pady=5)

        # Buttons
        buttons_frame = ttk.Frame(new_sale_frame)
        buttons_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(buttons_frame, text="Record Sale", command=self.record_sale).grid(row=0, column=0, padx=5)
        ttk.Button(buttons_frame, text="Clear", command=self.clear_sale_form).grid(row=0, column=1, padx=5)

        # Load initial data
        self.load_sales()
        self.load_car_combo()
        self.load_customer_combo()

    def setup_users_tab(self):
        # Only admins can access this tab
        if self.user_info[3] != 'admin':
            return

        # Left frame for user list
        left_frame = ttk.Frame(self.users_tab)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # User list
        user_list_frame = ttk.LabelFrame(left_frame, text="User List")
        user_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Treeview for user list
        columns = ('id', 'username', 'full_name', 'role', 'created_at')
        self.user_tree = ttk.Treeview(user_list_frame, columns=columns, show='headings')

        # Define headings
        self.user_tree.heading('id', text='ID')
        self.user_tree.heading('username', text='Username')
        self.user_tree.heading('full_name', text='Full Name')
        self.user_tree.heading('role', text='Role')
        self.user_tree.heading('created_at', text='Created At')

        # Define columns
        self.user_tree.column('id', width=50)
        self.user_tree.column('username', width=100)
        self.user_tree.column('full_name', width=150)
        self.user_tree.column('role', width=100)
        self.user_tree.column('created_at', width=150)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(user_list_frame, orient=tk.VERTICAL, command=self.user_tree.yview)
        self.user_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.user_tree.pack(fill=tk.BOTH, expand=True)

        # Bind select event
        self.user_tree.bind('<<TreeviewSelect>>', self.on_user_select)

        # Right frame for user details
        right_frame = ttk.Frame(self.users_tab)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=5, pady=5)

        # User details frame
        user_details_frame = ttk.LabelFrame(right_frame, text="User Details")
        user_details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # User details form
        ttk.Label(user_details_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.user_username_var = tk.StringVar()
        ttk.Entry(user_details_frame, textvariable=self.user_username_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(user_details_frame, text="Full Name:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.user_fullname_var = tk.StringVar()
        ttk.Entry(user_details_frame, textvariable=self.user_fullname_var).grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(user_details_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.user_password_var = tk.StringVar()
        ttk.Entry(user_details_frame, textvariable=self.user_password_var, show="*").grid(row=2, column=1, padx=5,
                                                                                          pady=5)

        ttk.Label(user_details_frame, text="Role:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.user_role_var = tk.StringVar()
        role_combo = ttk.Combobox(user_details_frame, textvariable=self.user_role_var)
        role_combo['values'] = ('employee', 'manager', 'admin')
        role_combo.grid(row=3, column=1, padx=5, pady=5)

        # Buttons frame
        buttons_frame = ttk.Frame(user_details_frame)
        buttons_frame.grid(row=4, column=0, columnspan=2, pady=10)

        ttk.Button(buttons_frame, text="Add New", command=self.add_user).grid(row=0, column=0, padx=5)
        ttk.Button(buttons_frame, text="Update", command=self.update_user).grid(row=0, column=1, padx=5)
        ttk.Button(buttons_frame, text="Delete", command=self.delete_user).grid(row=0, column=2, padx=5)
        ttk.Button(buttons_frame, text="Clear", command=self.clear_user_form).grid(row=0, column=3, padx=5)

        # Load initial data
        self.load_users()

    # Inventory methods
    def load_cars(self):
        # Clear existing items
        for item in self.car_tree.get_children():
            self.car_tree.delete(item)

        # Get all cars from database with creator username
        self.cursor.execute("""
        SELECT c.id, c.make, c.model, c.year, c.color, c.price, c.status, 
               COALESCE(u.username, 'Unknown') as created_by
        FROM cars c
        LEFT JOIN users u ON c.created_by = u.id
        """)
        cars = self.cursor.fetchall()

        # Insert into treeview
        for car in cars:
            self.car_tree.insert('', tk.END, values=car)

    def search_cars(self):
        search_term = f"%{self.search_var.get()}%"

        # Clear existing items
        for item in self.car_tree.get_children():
            self.car_tree.delete(item)

        # Search in database
        self.cursor.execute("""
        SELECT c.id, c.make, c.model, c.year, c.color, c.price, c.status, 
               COALESCE(u.username, 'Unknown') as created_by
        FROM cars c
        LEFT JOIN users u ON c.created_by = u.id
        WHERE c.make LIKE ? OR c.model LIKE ? OR c.year LIKE ? OR c.color LIKE ? OR c.status LIKE ?
        """, (search_term, search_term, search_term, search_term, search_term))

        cars = self.cursor.fetchall()

        # Insert into treeview
        for car in cars:
            self.car_tree.insert('', tk.END, values=car)

    def clear_search(self):
        self.search_var.set('')
        self.load_cars()

    def on_car_select(self, event):
        # Get selected item
        selected_item = self.car_tree.selection()
        if not selected_item:
            return

        # Get values
        values = self.car_tree.item(selected_item[0], 'values')

        # Set form values
        self.make_var.set(values[1])
        self.model_var.set(values[2])
        self.year_var.set(values[3])
        self.color_var.set(values[4])
        self.price_var.set(values[5])
        self.status_var.set(values[6])

        # Store selected car ID
        self.selected_car_id = values[0]

    def add_car(self):
        # Get form values
        make = self.make_var.get()
        model = self.model_var.get()
        year = self.year_var.get()
        color = self.color_var.get()
        price = self.price_var.get()
        status = self.status_var.get() or 'Available'

        # Validate
        if not make or not model or not year or not price:
            messagebox.showerror("Error", "Make, Model, Year, and Price are required!")
            return

        try:
            year = int(year)
            price = float(price)
        except ValueError:
            messagebox.showerror("Error", "Year must be a number and Price must be a decimal number!")
            return

        # Insert into database with user info
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.cursor.execute("""
        INSERT INTO cars (make, model, year, color, price, status, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (make, model, year, color, price, status, self.user_info[0], current_time))

        self.conn.commit()

        # Refresh list
        self.load_cars()
        self.load_car_combo()

        # Clear form
        self.clear_car_form()

        messagebox.showinfo("Success", "Car added successfully!")

    def update_car(self):
        # Check if a car is selected
        if not hasattr(self, 'selected_car_id'):
            messagebox.showerror("Error", "Please select a car to update!")
            return

        # Get form values
        make = self.make_var.get()
        model = self.model_var.get()
        year = self.year_var.get()
        color = self.color_var.get()
        price = self.price_var.get()
        status = self.status_var.get()

        # Validate
        if not make or not model or not year or not price:
            messagebox.showerror("Error", "Make, Model, Year, and Price are required!")
            return

        try:
            year = int(year)
            price = float(price)
        except ValueError:
            messagebox.showerror("Error", "Year must be a number and Price must be a decimal number!")
            return

        # Update database
        self.cursor.execute("""
        UPDATE cars
        SET make = ?, model = ?, year = ?, color = ?, price = ?, status = ?
        WHERE id = ?
        """, (make, model, year, color, price, status, self.selected_car_id))

        self.conn.commit()

        # Refresh list
        self.load_cars()
        self.load_car_combo()

        # Clear form
        self.clear_car_form()

        messagebox.showinfo("Success", "Car updated successfully!")

    def delete_car(self):
        # Check if a car is selected
        if not hasattr(self, 'selected_car_id'):
            messagebox.showerror("Error", "Please select a car to delete!")
            return

        # Confirm deletion
        if not messagebox.askyesno("Confirm", "Are you sure you want to delete this car?"):
            return

        # Check if car is used in sales
        self.cursor.execute("SELECT COUNT(*) FROM sales WHERE car_id = ?", (self.selected_car_id,))
        count = self.cursor.fetchone()[0]

        if count > 0:
            messagebox.showerror("Error", "Cannot delete car that has sales records!")
            return

        # Delete from database
        self.cursor.execute("DELETE FROM cars WHERE id = ?", (self.selected_car_id,))
        self.conn.commit()

        # Refresh list
        self.load_cars()
        self.load_car_combo()

        # Clear form
        self.clear_car_form()

        messagebox.showinfo("Success", "Car deleted successfully!")

    def clear_car_form(self):
        self.make_var.set('')
        self.model_var.set('')
        self.year_var.set('')
        self.color_var.set('')
        self.price_var.set('')
        self.status_var.set('')

        if hasattr(self, 'selected_car_id'):
            delattr(self, 'selected_car_id')

    # Customer methods
    def load_customers(self):
        # Clear existing items
        for item in self.customer_tree.get_children():
            self.customer_tree.delete(item)

        # Get all customers from database with creator username
        self.cursor.execute("""
        SELECT c.id, c.name, c.phone, c.email, c.address, 
               COALESCE(u.username, 'Unknown') as created_by
        FROM customers c
        LEFT JOIN users u ON c.created_by = u.id
        """)
        customers = self.cursor.fetchall()

        # Insert into treeview
        for customer in customers:
            self.customer_tree.insert('', tk.END, values=customer)

    def search_customers(self):
        search_term = f"%{self.customer_search_var.get()}%"

        # Clear existing items
        for item in self.customer_tree.get_children():
            self.customer_tree.delete(item)

        # Search in database
        self.cursor.execute("""
        SELECT c.id, c.name, c.phone, c.email, c.address, 
               COALESCE(u.username, 'Unknown') as created_by
        FROM customers c
        LEFT JOIN users u ON c.created_by = u.id
        WHERE c.name LIKE ? OR c.phone LIKE ? OR c.email LIKE ? OR c.address LIKE ?
        """, (search_term, search_term, search_term, search_term))

        customers = self.cursor.fetchall()

        # Insert into treeview
        for customer in customers:
            self.customer_tree.insert('', tk.END, values=customer)

    def clear_customer_search(self):
        self.customer_search_var.set('')
        self.load_customers()

    def on_customer_select(self, event):
        # Get selected item
        selected_item = self.customer_tree.selection()
        if not selected_item:
            return

        # Get values
        values = self.customer_tree.item(selected_item[0], 'values')

        # Set form values
        self.customer_name_var.set(values[1])
        self.customer_phone_var.set(values[2])
        self.customer_email_var.set(values[3])
        self.customer_address_var.set(values[4])

        # Store selected customer ID
        self.selected_customer_id = values[0]

    def add_customer(self):
        # Get form values
        name = self.customer_name_var.get()
        phone = self.customer_phone_var.get()
        email = self.customer_email_var.get()
        address = self.customer_address_var.get()

        # Validate
        if not name or not phone:
            messagebox.showerror("Error", "Name and Phone are required!")
            return

        # Insert into database with user info
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.cursor.execute("""
        INSERT INTO customers (name, phone, email, address, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (name, phone, email, address, self.user_info[0], current_time))

        self.conn.commit()

        # Refresh list
        self.load_customers()
        self.load_customer_combo()

        # Clear form
        self.clear_customer_form()

        messagebox.showinfo("Success", "Customer added successfully!")

    def update_customer(self):
        # Check if a customer is selected
        if not hasattr(self, 'selected_customer_id'):
            messagebox.showerror("Error", "Please select a customer to update!")
            return

        # Get form values
        name = self.customer_name_var.get()
        phone = self.customer_phone_var.get()
        email = self.customer_email_var.get()
        address = self.customer_address_var.get()

        # Validate
        if not name or not phone:
            messagebox.showerror("Error", "Name and Phone are required!")
            return

        # Update database
        self.cursor.execute("""
        UPDATE customers
        SET name = ?, phone = ?, email = ?, address = ?
        WHERE id = ?
        """, (name, phone, email, address, self.selected_customer_id))

        self.conn.commit()

        # Refresh list
        self.load_customers()
        self.load_customer_combo()

        # Clear form
        self.clear_customer_form()

        messagebox.showinfo("Success", "Customer updated successfully!")

    def delete_customer(self):
        # Check if a customer is selected
        if not hasattr(self, 'selected_customer_id'):
            messagebox.showerror("Error", "Please select a customer to delete!")
            return

        # Confirm deletion
        if not messagebox.askyesno("Confirm", "Are you sure you want to delete this customer?"):
            return

        # Check if customer is used in sales
        self.cursor.execute("SELECT COUNT(*) FROM sales WHERE customer_id = ?", (self.selected_customer_id,))
        count = self.cursor.fetchone()[0]

        if count > 0:
            messagebox.showerror("Error", "Cannot delete customer that has sales records!")
            return

        # Delete from database
        self.cursor.execute("DELETE FROM customers WHERE id = ?", (self.selected_customer_id,))
        self.conn.commit()

        # Refresh list
        self.load_customers()
        self.load_customer_combo()

        # Clear form
        self.clear_customer_form()

        messagebox.showinfo("Success", "Customer deleted successfully!")

    def clear_customer_form(self):
        self.customer_name_var.set('')
        self.customer_phone_var.set('')
        self.customer_email_var.set('')
        self.customer_address_var.set('')

        if hasattr(self, 'selected_customer_id'):
            delattr(self, 'selected_customer_id')

    # Sales methods
    def load_sales(self):
        # Clear existing items
        for item in self.sales_tree.get_children():
            self.sales_tree.delete(item)

        # Get all sales with car, customer, and user details
        self.cursor.execute("""
        SELECT s.id, c.make || ' ' || c.model || ' (' || c.year || ')', 
               cu.name, s.sale_date, s.sale_price,
               COALESCE(u.username, 'Unknown') as created_by
        FROM sales s
        JOIN cars c ON s.car_id = c.id
        JOIN customers cu ON s.customer_id = cu.id
        LEFT JOIN users u ON s.created_by = u.id
        ORDER BY s.sale_date DESC
        """)

        sales = self.cursor.fetchall()

        # Insert into treeview
        for sale in sales:
            self.sales_tree.insert('', tk.END, values=sale)

    def load_car_combo(self):
        # Get available cars
        self.cursor.execute("""
        SELECT id, make || ' ' || model || ' (' || year || ')' as car_name
        FROM cars
        WHERE status = 'Available'
        """)

        cars = self.cursor.fetchall()

        # Set combobox values
        self.car_combo['values'] = [f"{car[1]} [ID: {car[0]}]" for car in cars]

    def load_customer_combo(self):
        # Get customers
        self.cursor.execute("SELECT id, name FROM customers")
        customers = self.cursor.fetchall()

        # Set combobox values
        self.customer_combo['values'] = [f"{customer[1]} [ID: {customer[0]}]" for customer in customers]

    def record_sale(self):
        # Get form values
        car_selection = self.sale_car_var.get()
        customer_selection = self.sale_customer_var.get()
        sale_price = self.sale_price_var.get()

        # Validate
        if not car_selection or not customer_selection or not sale_price:
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            sale_price = float(sale_price)
        except ValueError:
            messagebox.showerror("Error", "Sale Price must be a decimal number!")
            return

        # Extract IDs from selections
        try:
            car_id = int(car_selection.split("[ID: ")[1].split("]")[0])
            customer_id = int(customer_selection.split("[ID: ")[1].split("]")[0])
        except (IndexError, ValueError):
            messagebox.showerror("Error", "Invalid car or customer selection!")
            return

        # Get current date
        sale_date = datetime.now().strftime("%Y-%m-%d")
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Insert into database with user info
        self.cursor.execute("""
        INSERT INTO sales (car_id, customer_id, sale_date, sale_price, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (car_id, customer_id, sale_date, sale_price, self.user_info[0], current_time))

        # Update car status
        self.cursor.execute("UPDATE cars SET status = 'Sold' WHERE id = ?", (car_id,))

        self.conn.commit()

        # Refresh lists
        self.load_sales()
        self.load_cars()
        self.load_car_combo()

        # Clear form
        self.clear_sale_form()

        messagebox.showinfo("Success", "Sale recorded successfully!")

    def clear_sale_form(self):
        self.sale_car_var.set('')
        self.sale_customer_var.set('')
        self.sale_price_var.set('')

    # User methods (admin only)
    def load_users(self):
        # Only admins can access this
        if self.user_info[3] != 'admin':
            return

        # Clear existing items
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)

        # Get all users from database
        self.cursor.execute("SELECT id, username, full_name, role, created_at FROM users")
        users = self.cursor.fetchall()

        # Insert into treeview
        for user in users:
            self.user_tree.insert('', tk.END, values=user)

    def on_user_select(self, event):
        # Only admins can access this
        if self.user_info[3] != 'admin':
            return

        # Get selected item
        selected_item = self.user_tree.selection()
        if not selected_item:
            return

        # Get values
        values = self.user_tree.item(selected_item[0], 'values')

        # Set form values
        self.user_username_var.set(values[1])
        self.user_fullname_var.set(values[2])
        self.user_password_var.set('')  # Don't show password
        self.user_role_var.set(values[3])

        # Store selected user ID
        self.selected_user_id = values[0]

    def add_user(self):
        # Only admins can access this
        if self.user_info[3] != 'admin':
            return

        # Get form values
        username = self.user_username_var.get()
        full_name = self.user_fullname_var.get()
        password = self.user_password_var.get()
        role = self.user_role_var.get()

        # Validate
        if not username or not full_name or not password or not role:
            messagebox.showerror("Error", "All fields are required!")
            return

        # Check if username exists
        self.cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        if self.cursor.fetchone()[0] > 0:
            messagebox.showerror("Error", "Username already exists!")
            return

        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Insert into database
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.cursor.execute("""
        INSERT INTO users (username, password, full_name, role, created_at)
        VALUES (?, ?, ?, ?, ?)
        """, (username, hashed_password, full_name, role, current_time))

        self.conn.commit()

        # Refresh list
        self.load_users()

        # Clear form
        self.clear_user_form()

        messagebox.showinfo("Success", "User added successfully!")

    def update_user(self):
        # Only admins can access this
        if self.user_info[3] != 'admin':
            return

        # Check if a user is selected
        if not hasattr(self, 'selected_user_id'):
            messagebox.showerror("Error", "Please select a user to update!")
            return

        # Get form values
        username = self.user_username_var.get()
        full_name = self.user_fullname_var.get()
        password = self.user_password_var.get()
        role = self.user_role_var.get()

        # Validate
        if not username or not full_name or not role:
            messagebox.showerror("Error", "Username, Full Name, and Role are required!")
            return

        # Check if username exists for other users
        self.cursor.execute("SELECT COUNT(*) FROM users WHERE username = ? AND id != ?",
                            (username, self.selected_user_id))
        if self.cursor.fetchone()[0] > 0:
            messagebox.showerror("Error", "Username already exists!")
            return

        # Update database
        if password:
            # Hash the password
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            self.cursor.execute("""
            UPDATE users
            SET username = ?, password = ?, full_name = ?, role = ?
            WHERE id = ?
            """, (username, hashed_password, full_name, role, self.selected_user_id))
        else:
            # Don't update password
            self.cursor.execute("""
            UPDATE users
            SET username = ?, full_name = ?, role = ?
            WHERE id = ?
            """, (username, full_name, role, self.selected_user_id))

        self.conn.commit()

        # Refresh list
        self.load_users()

        # Clear form
        self.clear_user_form()

        messagebox.showinfo("Success", "User updated successfully!")

    def delete_user(self):
        # Only admins can access this
        if self.user_info[3] != 'admin':
            return

        # Check if a user is selected
        if not hasattr(self, 'selected_user_id'):
            messagebox.showerror("Error", "Please select a user to delete!")
            return

        # Prevent deleting yourself
        if int(self.selected_user_id) == self.user_info[0]:
            messagebox.showerror("Error", "You cannot delete your own account!")
            return

        # Confirm deletion
        if not messagebox.askyesno("Confirm", "Are you sure you want to delete this user?"):
            return

        # Delete from database
        self.cursor.execute("DELETE FROM users WHERE id = ?", (self.selected_user_id,))
        self.conn.commit()

        # Refresh list
        self.load_users()

        # Clear form
        self.clear_user_form()

        messagebox.showinfo("Success", "User deleted successfully!")

    def clear_user_form(self):
        self.user_username_var.set('')
        self.user_fullname_var.set('')
        self.user_password_var.set('')
        self.user_role_var.set('')

        if hasattr(self, 'selected_user_id'):
            delattr(self, 'selected_user_id')

    def logout(self):
        # Confirm logout
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            # Clear the main window
            for widget in self.root.winfo_children():
                widget.destroy()

            # Show login window with a new callback function
            LoginWindow(self.root, self.conn, lambda user_info: CarDealershipApp(self.root, user_info))


def main():
    root = tk.Tk()

    # Connect to database - use file-based database instead of in-memory
    conn = sqlite3.connect('car_dealer.db')

    # Start with login window
    login_window = LoginWindow(root, conn, lambda user_info: CarDealershipApp(root, user_info))

    root.mainloop()


if __name__ == "__main__":
    main()