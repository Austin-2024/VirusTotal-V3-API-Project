import tkinter as tk
from tkinter import filedialog

root = tk.Tk()
root.withdraw()

filePath = filedialog.askopenfilename()
if filePath:
    with open("filepath.txt", "w") as f:
        f.write(filePath)
        
        f.close()

exit()