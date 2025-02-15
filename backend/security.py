import json
import AES_GCM
import base64
from files import backendpath

class secure_module:
    """Security module which stores important and confidental information.
    Information is stored encrypted and password protected. 
    The module also provides the WebEncr and WebDecr functions which encrypts and decrypts any object with AES-GCM 256-bit encryption.
    """
    def __init__(self, pwd: str = None):
        import getpass
        from os import path
        if pwd == None:
            pwd = getpass.getpass('Type in your encryption password -->')
        from hashlib import sha256
        self.secure_module_key = sha256(pwd.encode('utf-8'), usedforsecurity=True).digest()
        if not path.exists(backendpath('data.secrets')):
            print('initializing secure_module')
            self.init_secure_module()
        self.load_secrets()
        #print('secure_module version: ',self.secrets['Version'])
    
    def load_secrets(self) -> None:
        with open(backendpath('data.secrets'),'rb') as f:
            self.secrets = f.read()
        self.secrets = AES_GCM.decrypt(self.secrets,self.secure_module_key).decode('utf-8')
        self.secrets: dict = json.loads(self.secrets)
        self.webkey = self.secrets['WebKeyAES']
        self.webkey = base64.b64decode(self.webkey)
        
    def add_secret(self, id: str, data) -> None:
        self.secrets.update({id: data})
        secr = json.dumps(self.secrets).encode('utf-8')
        secr = AES_GCM.encrypt(secr, self.secure_module_key)
        with open(backendpath('data.secrets'),'wb') as f:
            f.write(secr)
    
    def get_secret(self, id: str):
        return self.secrets[id]
    
    def init_secure_module(self) -> None:
        #Init runs, if no existing data.secrets file was found
        self.secrets = {}
        self.add_secret('Version','v1.2.0')
        self.add_secret('WebKeyAES',base64.b64encode(AES_GCM.random_key()).decode('ascii'))
        ##Here you can initialize the module with secrets, make sure to delete them from the source code imediately after initialization
        self.add_secret('something','some data')
        print(self.secrets,'secure_module initialized')
    
    def WebEncr(self,data) -> bytes:
        """Encrypts stuff, without having to worry about the key or other stuff

        Args:
            data (Any): Some object, which will be encrypted. Not bytes!

        Returns:
            bytes: The encrypted data
        """
        data: str = json.dumps(data)
        encr: bytes = AES_GCM.encrypt(data.encode('ascii'),self.webkey)
        return encr
    
    def WebDecr(self, data: bytes):
        """Decrypts stuff, without you having to worry about the key or other stuff

        Args:
            data (bytes): The encrypted bytes from the database

        Returns:
            Any: The decrypted data, in whatever type it was before encryption
        """
        decr: bytes = AES_GCM.decrypt(data,self.webkey)
        data = json.loads(decr.decode('ascii'))
        return data