import sqlite3
from scapy.all import *

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

    def add_trusted_server(self, server_ip, server_mac):
        print("adding trusted server")
        query = 'INSERT INTO DHCP_SERVERS VALUES ("' + server_ip + '", "' + server_mac + '");'
        self.conn.execute(query)
        self.conn.commit()
        server = {'ip': server_ip, 'mac': server_mac}
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
    				(IP 	VARCHAR 		NOT NULL,
    				 MAC 	VARCHAR 		NOT NULL);''')

    def load_db(self, conn):
        trusted_servers = []
        for row in conn.execute('SELECT * FROM DHCP_SERVERS;'):
            server = {'ip': row[0], 'mac': row[1]}
            trusted_servers.append(server)
        return trusted_servers

    def update_view(self):
        self.parent.updateDhcpTv(self.trusted_servers)
