from Tkinter import *

class UIMenu:
    def __init__(self, parent):
        self.menu = Menu(parent, bg = "#000000", fg = "#FFFFFF")

        self.fileMenu = Menu(self.menu)
        self.menu.add_cascade(label='File', menu=self.fileMenu)
        self.fileMenu.add_command(label='Quit', command=quit)

        self.helpMenu = Menu(self.menu)
        self.menu.add_cascade(label='Help', menu=self.helpMenu)
        self.helpMenu.add_command(label='User guide')
