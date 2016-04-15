import Tkinter as tk
from Tkinter import *
import ttk
import platform
from scapy.all import *
from UIMenu import UIMenu
from NetworkPlotter import NetworkPlotter
import matplotlib
matplotlib.use('TkAgg')
from Sniffer import Sniffer
from Updater import Updater
from DhcpDefender import DhcpDefender
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.figure import Figure

class MainApplication(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        #CONFIGURE BUTTON STYLES 
        s = ttk.Style()
        s.configure('TButton',background = 'black', foreground = 'white',
                font='Helvetica')
        s.map('TButton',
                background=[('disabled','black'),('active','black')]
                )


        #UIMENU 
        self.uiMenu = UIMenu(self)
        self.parent.config(menu=self.uiMenu.menu)
        
        #TOOLBAR + STATUS BAR 
        self.toolbar = Frame(self.parent)
        self.toolbarButton1 = ttk.Button(self.toolbar, text='Button', style='TButton')
        self.toolbarButton1.pack(side=LEFT, padx=2, pady=2)
        self.toolbar.pack(side=TOP, fill=X)

        self.statusbar = Label(self.parent, text='Statusbar', bd=1, relief=SUNKEN, anchor=W, bg = "#000000", fg = "#FFFFFF")
        self.statusbar.pack(side=BOTTOM, fill=X)
        #networkPlotter = NetworkPlotter(root)

        #MAIN UI 
        self.notebook = ttk.Notebook(self)
        self.frameSniff = ttk.Frame(self.notebook)
        self.frameArp = ttk.Frame(self.notebook)
        self.frameDhcp = ttk.Frame(self.notebook)
        self.frameSysInfo = ttk.Frame(self.notebook)
        self.notebook.add(self.frameSniff, text='Sniffer')
        self.notebook.add(self.frameArp, text='ARP')
        self.notebook.add(self.frameDhcp, text='DHCP Servers')
        self.notebook.add(self.frameSysInfo, text='System Info')
        self.notebook.pack(fill=X)
        

        #LABELFRAME STYLE 
        s1 = ttk.Style()
        s1.configure('TLabelframe.Label',font="Helvetica") 


        self.sniffLabelFrame = ttk.LabelFrame(self.frameSniff, text="Sniffer", style = "TLabelframe.Label")
        self.sniffLabelFrame.pack(padx=10, pady=10)
        self.sniffButton = ttk.Button(self.sniffLabelFrame, text="Sniff", command=self.beginSniff, style='TButton')
        self.sniffButton.pack(side=LEFT)
        self.stopSniffButton = ttk.Button(self.sniffLabelFrame, text="Stop sniffing", command=self.stopSniff, state="disabled", style='TButton')
        self.stopSniffButton.pack(side=LEFT)

        self.sniffTv = ttk.Treeview(self.frameSniff)
        ysb = ttk.Scrollbar(self, orient='vertical', command=self.sniffTv.yview)
        xsb = ttk.Scrollbar(self, orient='horizontal', command=self.sniffTv.xview)
        self.sniffTv.configure(yscroll=ysb.set, xscroll=xsb.set)
        self.sniffTv['columns'] = ('senderip', 'sendermac', 'received')
        self.sniffTv.heading('#0', text='Description', anchor='w')
        self.sniffTv.column('#0', anchor='w')
        self.sniffTv.heading('senderip', text='Sender IP')
        self.sniffTv.column('senderip', anchor='center', width=100)
        self.sniffTv.heading('sendermac', text='Sender MAC')
        self.sniffTv.column('sendermac', anchor='center', width=100)
        self.sniffTv.heading('received', text='Received at')
        self.sniffTv.column('received', anchor='center', width=100)
        self.sniffTv.pack(fill=BOTH)

        self.arpLabel = tk.Label(self.frameArp, text="ARP cache")
        self.arpLabel.pack()
        self.arpTv = ttk.Treeview(self.frameArp)
        self.arpTv['columns'] = ('ip', 'status')
        self.arpTv.heading('#0', text='MAC address', anchor='w')
        self.arpTv.column('#0', anchor='w')
        self.arpTv.heading('ip', text='IP address')
        self.arpTv.column('ip', anchor='center', width=100)
        self.arpTv.heading('status', text='Status')
        self.arpTv.column('status', anchor='center', width=100)
        self.arpTv.pack(fill=X)

        self.addDhcpLabelFrame = ttk.LabelFrame(self.frameDhcp, text="Add trusted server", style='TLabelframe.Label')
        self.addDhcpLabelFrame.pack(padx=10, pady=10)
        self.addDhcpIpLabel = tk.Label(self.addDhcpLabelFrame, text="Server IP address")
        self.addDhcpIpLabel.pack()
        self.addDhcpIpEntry = tk.Entry(self.addDhcpLabelFrame)
        self.addDhcpIpEntry.pack()

        self.addDhcpMacLabel = tk.Label(self.addDhcpLabelFrame, text="Server Mac address")
        self.addDhcpMacLabel.pack()
        self.addDhcpMacEntry = tk.Entry(self.addDhcpLabelFrame)
        self.addDhcpMacEntry.pack()
        self.addDhcpButton = ttk.Button(self.addDhcpLabelFrame, text="Add", command=self.addDhcpButtonPressed, style = 'TButton')
        self.addDhcpButton.pack()

        self.dhcpTv = ttk.Treeview(self.frameDhcp)
        self.dhcpTv['columns'] = ('ip', 'mac', 'date')
        self.dhcpTv.heading('#0', text='Server name', anchor='w')
        self.dhcpTv.column('#0', anchor='w')
        self.dhcpTv.heading('ip', text='IP address')
        self.dhcpTv.column('ip', anchor='center', width=100)
        self.dhcpTv.heading('mac', text='MAC address')
        self.dhcpTv.column('mac', anchor='center', width=100)
        self.dhcpTv.heading('date', text='Date added')
        self.dhcpTv.column('date', anchor='center', width=100)
        self.dhcpTv.pack(fill=X)

        strVersion = 'Python ' + platform.python_version()
        self.versionLabel = tk.Label(self.frameSysInfo, text=strVersion)
        self.versionLabel.pack()
        strPlatform = 'Platform: ' + platform.platform()
        self.platformLabel = tk.Label(self.frameSysInfo, text=strPlatform)
        self.platformLabel.pack()

        self.dhcpDefender = DhcpDefender(self)

        #self.sniffer = Sniffer(1, 'Sniffer-1', 1, self)
        #self.sniffer.start()

        self.updater = Updater(1, 'Updater-1', 1, self)
        self.updater.start()

    def addDhcpButtonPressed(self):
        ip = self.addDhcpIpEntry.get()
        mac = self.addDhcpMacEntry.get().lower()
        isValidIp =re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip)
        macRe = re.compile(r'^([0-9A-F]{1,2})' + '\:([0-9A-F]{1,2})'*5 + '$', re.IGNORECASE)
        isValidMac = macRe.match(mac)
        if isValidIp and isValidMac:
            self.dhcpDefender.add_trusted_server(ip, mac)


    def beginSniff(self):
        self.sniffButton.config(state="disabled")
        self.stopSniffButton.config(state="normal")
        #self.sniffer.resume()

    def stopSniff(self):
        self.stopSniffButton.config(state="disabled")
        self.sniffButton.config(state="normal")
        #self.sniffer.pause()

    def updateSniffTv(self, packet):
        if packet[ARP].op == 1:
            response = 'Request: ' + packet[ARP].psrc + ' is asking about ' + packet[ARP].pdst
        elif packet[ARP].op == 2:
            response = 'Response: ' + packet[ARP].hwsrc + ' has address ' + packet[ARP].psrc
        self.sniffTv.insert("", 0, text=response, values=("192"," MAC", "Received at"))

    def updateDhcpTv(self, trusted_servers):
        self.dhcpTv.delete(*self.dhcpTv.get_children())
        for server in trusted_servers:
            self.dhcpTv.insert("", 0, text="Server name", values=(server['ip'], server['mac']))

    def import_arp_cache(self):
        self.arpTv.delete(*self.arpTv.get_children())
        out, err = Popen(['arp', '-na'], stdout=PIPE, stderr=PIPE).communicate()
        out = out.splitlines()
        for line in out:
            ip = self.find_between(line, '(', ')')
            mac = self.find_between(line, 'at ', ' on')
            self.arpTv.insert("", 0, text=mac, values=(ip, ""))

    def find_between(self, s, first, last):
        try:
            start = s.index(first) + len(first)
            end = s.index(last, start)
            return s[start:end]
        except ValueError:
            return ""

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApplication(root)
    app.pack(side="top", fill="both", expand="true")
    root.mainloop()
