import sqlite3
import datetime
from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.dhcp import DHCP


class DhcpDefender:
    def __init__(self, parent):
        self.parent = parent
        self.conn = self.conn_db()
        #self.init_db(self.conn)
        self.trusted_servers = self.load_db(self.conn)
        self.update_view()

    def check_dhcp_pkt(self, pkt):
        if pkt[DHCP] and pkt[DHCP].options[0][1] == 5:
            if pkt[IP].src != globals()['dhcp_server_ip'] or pkt[Ether].src != globals()['dhcp_server_mac']:
                print ("Unknown server with IP " + pkt[IP].src + " and MAC " + pkt[Ether].src + " acknowledged DHCP response")
            else:
                print("Correct server acknowledged DHCP response")

    def add_trusted_server(self, server_name, server_ip, server_mac):
        print("adding trusted server")
        timeStr = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        query = 'INSERT INTO DHCP_SERVERS VALUES ("' + server_name + '", "' + server_ip + '", "' + server_mac + '", "' + timeStr + '");'
        self.conn.execute(query)
        self.conn.commit()
        server = {'name': server_name, 'ip': server_ip, 'mac': server_mac, 'date': timeStr}
        self.trusted_servers.append(server)
        self.update_view()

    def remove_trusted_server(self, server_ip, server_nmac):
        print("remove trusted server")

    def conn_db(self):
        conn = sqlite3.connect('app.db')
        print "Connected to database successfully"
        return conn

    def init_db(self, conn):
        conn.execute("DROP TABLE IF EXISTS DHCP_SERVERS;")
        conn.execute('''CREATE TABLE DHCP_SERVERS
    				(NAME   VARCHAR         NOT NULL,
    				 IP 	VARCHAR 		NOT NULL,
    				 MAC 	VARCHAR 		NOT NULL,
    				 DATE   VARCHAR         NOT NULL);''')

    def load_db(self, conn):
        trusted_servers = []
        for row in conn.execute('SELECT * FROM DHCP_SERVERS;'):
            server = {'name': row[0], 'ip': row[1], 'mac': row[2], 'date': row[3]}
            trusted_servers.append(server)
        return trusted_servers

    def update_view(self):
        self.parent.updateDhcpTv(self.trusted_servers)

    def clear_db(self):
        self.init_db(self.conn)
        self.trusted_servers = []
        self.update_view()


    def dhcp_pkt_callback(self, packet):
        for entry in self.trusted_servers:
            if entry['ip'] == packet[IP].src and entry['mac'] == packet[Ether].src:
                return 1
        return 0