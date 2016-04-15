import threading
import time
from subprocess import Popen, PIPE

class Updater(threading.Thread):
    def __init__(self, threadID, name, counter, app):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.app = app
        print('Updater initiated')

    def run(self):
        self.update()
        time.sleep(5)

    def update(self):
        self.app.import_arp_cache()