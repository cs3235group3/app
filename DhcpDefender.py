import sqlite3

class DhcpDefender:
    def __init__(self, parent):
        self.parent = parent
        self.conn = self.conn_db()
        self.init_db(self.conn)
        self.trusted_servers = self.load_db(self.conn)
        self.get_trusted_servers()

    def get_trusted_servers(self):
        print("getting trusted servers")


    def add_trusted_server(self):
        print("adding trusted server")

    def remove_trusted_server(self):
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