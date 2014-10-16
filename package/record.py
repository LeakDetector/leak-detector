from Tkinter import Tk, BOTH, RIGHT, RAISED, BOTTOM
from Tkinter import Frame, Button


class App(Frame):
    """docstring for App"""
    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        self.initUI()
    
    def initUI(self):
        self.parent.title("Leak Detector")
        
        self.layout()
        
        self.pack(fill=BOTH, expand=1)
        
    def layout(self):
        
        quit = Button(self, text="Quit", command=self.quit)
        quit.pack(side=BOTTOM, padx=5, pady=5)
        
def main():
    root = Tk()
    root.geometry("640x250+300+300")
    app = App(root)
    root.mainloop()  
    
if __name__ == '__main__':
    main()
        
                