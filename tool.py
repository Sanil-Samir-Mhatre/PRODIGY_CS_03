import re
import tkinter as tk
from tkinter import messagebox, ttk

def assess_password_strength(password):
    # Evaluate password strength based on common rules
    strength_score = 0
    feedback = []

    if len(password) >= 8:
        strength_score += 1
    else:
        feedback.append("Make it at least 8 characters long.")
    
    if re.search(r'[A-Z]', password):
        strength_score += 1
    else:
        feedback.append("Include at least one uppercase letter.")
    
    if re.search(r'[a-z]', password):
        strength_score += 1
    else:
        feedback.append("Include at least one lowercase letter.")
    
    if re.search(r'\d', password):
        strength_score += 1
    else:
        feedback.append("Include at least one number.")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength_score += 1
    else:
        feedback.append("Add a special character (e.g., @, #, !, $).")
    
    if strength_score == 5:
        return "Strong", "Great password! It's secure. :)"
    elif strength_score >= 3:
        return "Medium", "Decent password, but you can improve it! " + ' '.join(feedback)
    else:
        return "Weak", "Weak password! " + ' '.join(feedback)

def check_password(*args):
    # Check the password as user types and give feedback
    password = password_entry.get()
    strength, feedback = assess_password_strength(password)
    strength_label.config(text=f"Strength: {strength}")
    feedback_label.config(text=feedback)

    strength_levels = {"Weak": 20, "Medium": 60, "Strong": 100}
    progress_bar["value"] = strength_levels.get(strength, 0)

def toggle_password_visibility():
    # Let user see/hide the password
    if password_entry.cget("show") == "*":
        password_entry.config(show="")
        toggle_button.config(text="Hide")
    else:
        password_entry.config(show="*")
        toggle_button.config(text="Show")

def copy_to_clipboard():
    # Copy the password to clipboard
    root.clipboard_clear()
    root.clipboard_append(password_entry.get())
    root.update()
    messagebox.showinfo("Copied", "Password copied to clipboard!")

def refresh():
    # Clear everything on screen
    password_entry.delete(0, tk.END)
    strength_label.config(text="")
    feedback_label.config(text="")
    progress_bar["value"] = 0

# Setup main application window
root = tk.Tk()
root.title("Password Complexity Checker")
root.geometry("1920x1080")
root.configure(bg="#f0f0f0")

# Header
tk.Label(root, text="Enter your password:", font=("Arial", 28, "bold"), bg="#f0f0f0").pack(pady=40)

# Password input and toggle
frame = tk.Frame(root, bg="#f0f0f0")
frame.pack(pady=20)

password_entry = tk.Entry(frame, show="*", width=40, font=("Arial", 22))
password_entry.pack(side=tk.LEFT, padx=10)
password_entry.bind("<KeyRelease>", check_password)

toggle_button = tk.Button(frame, text="Show", command=toggle_password_visibility, font=("Arial", 18))
toggle_button.pack(side=tk.LEFT, padx=10)

# Button to manually check
check_button = tk.Button(root, text="Check Password", command=check_password, font=("Arial", 22), bg="#4CAF50", fg="white", width=20)
check_button.pack(pady=30)

# Strength label
strength_label = tk.Label(root, text="", font=("Arial", 22, "bold"), bg="#f0f0f0")
strength_label.pack(pady=10)

# Progress bar
progress_bar = ttk.Progressbar(root, length=800, mode="determinate")
progress_bar.pack(pady=10)

# Feedback text
feedback_label = tk.Label(root, text="", font=("Arial", 18), wraplength=1200, justify="center", bg="#f0f0f0")
feedback_label.pack(pady=10)

# Copy button
copy_button = tk.Button(root, text="Copy Password", command=copy_to_clipboard, font=("Arial", 20), bg="#2196F3", fg="white", width=20)
copy_button.pack(pady=20)

# Refresh/reset
refresh_button = tk.Button(root, text="Refresh", command=refresh, font=("Arial", 20), bg="#f44336", fg="white", width=20)
refresh_button.pack(pady=10)

root.mainloop()
