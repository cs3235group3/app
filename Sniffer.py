from scapy.all import *
import threading
import time

class Sniffer(threading.Thread):
    def __init__(self, threadID, name, counter, app):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.app = app
        self.paused = True
        self.pause_cond = threading.Condition(threading.Lock())
        self.pause_cond.acquire()
        print('Sniffer initiated')

    def run(self):
        while True:
            with self.pause_cond:
                while self.paused:
                    self.pause_cond.wait()
                self.sniff()
            time.sleep(3)

    def resume(self):
        self.paused = False
        # Notify so thread will wake after lock released
        self.pause_cond.notify()
        # Now release the lock
        self.pause_cond.release()

    def pause(self):
        self.paused = True
        # If in sleep, we acquire immediately, otherwise we wait for thread
        # to release condition. In race, worker will still see self.paused
        # and begin waiting until it's set back to False
        self.pause_cond.acquire()

    def sniff(self):
        sniff(prn=self.packet_callback, filter="arp", store=0, count=1)

    def packet_callback(self, packet):
        self.app.updateSniffTv(packet)