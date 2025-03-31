import re
import tkinter as tk
from tkinter import messagebox, ttk

def assess_password_strength(password):
    """
    Assess password strength based on multiple criteria.
    """
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
        return "Strong", "Great password! It's secure. 😊"
    elif strength_score >= 3:
        return "Medium", "Decent password, but you can improve it! " + ' '.join(feedback)
    else:
        return "Weak", "Weak password! " + ' '.join(feedback)

def check_password(*args):
    """
    Check the password strength and update labels & progress bar.
    """
    password = password_entry.get()
    strength, feedback = assess_password_strength(password)
    strength_label.config(text=f"Strength: {strength}")
    feedback_label.config(text=feedback)
    
    strength_levels = {"Weak": 20, "Medium": 60, "Strong": 100}
    progress_bar["value"] = strength_levels.get(strength, 0)

def toggle_password_visibility():
    """Toggle password visibility."""
    if password_entry.cget("show") == "*":
        password_entry.config(show="")
        toggle_button.config(text="Hide")
    else:
        password_entry.config(show="*")
        toggle_button.config(text="Show")

def copy_to_clipboard():
    """Copy password to clipboard."""
    root.clipboard_clear()
    root.clipboard_append(password_entry.get())
    root.update()
    messagebox.showinfo("Copied", "Password copied to clipboard!")

def refresh():
    """Reset all fields."""
    password_entry.delete(0, tk.END)
    strength_label.config(text="")
    feedback_label.config(text="")
    progress_bar["value"] = 0

# GUI Setup
root = tk.Tk()
root.title("Password Complexity Checker")
root.geometry("500x400")
root.resizable(False, False)
root.configure(bg="#f0f0f0")

# Layout
tk.Label(root, text="Enter your password:", font=("Arial", 14), bg="#f0f0f0").pack(pady=10)
frame = tk.Frame(root, bg="#f0f0f0")
frame.pack(pady=5)

password_entry = tk.Entry(frame, show="*", width=30, font=("Arial", 12))
password_entry.pack(side=tk.LEFT, padx=5)
password_entry.bind("<KeyRelease>", check_password)  # Live update strength

toggle_button = tk.Button(frame, text="Show", command=toggle_password_visibility, font=("Arial", 10))
toggle_button.pack(side=tk.LEFT)

check_button = tk.Button(root, text="Check Password", command=check_password, font=("Arial", 12), bg="#4CAF50", fg="white")
check_button.pack(pady=10)

strength_label = tk.Label(root, text="", font=("Arial", 12, "bold"), bg="#f0f0f0")
strength_label.pack(pady=5)

progress_bar = ttk.Progressbar(root, length=300, mode="determinate")
progress_bar.pack(pady=5)

feedback_label = tk.Label(root, text="", font=("Arial", 10), wraplength=400, justify="center", bg="#f0f0f0")
feedback_label.pack(pady=5)

copy_button = tk.Button(root, text="Copy Password", command=copy_to_clipboard, font=("Arial", 12), bg="#2196F3", fg="white")
copy_button.pack(pady=5)

refresh_button = tk.Button(root, text="Refresh", command=refresh, font=("Arial", 12), bg="#f44336", fg="white")
refresh_button.pack(pady=10)

root.mainloop()
