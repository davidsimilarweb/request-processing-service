import jwt

class AppStoreToken:
    ip: str
    host: str
    token: str
    expiration: str | None

    def __init__(self, ip: str, host: str, token: str, expiration = None, remove_bearer = True):
        self.ip = ip
        self.host = host
        if remove_bearer:
            self.token = token.replace('Bearer ', '').strip()
        else:
            self.token = token
        self.expiration = expiration

    def augment(self):
        """Extracts the expiration from the token itself"""
        self.expiration = jwt.decode(self.token, options={"verify_signature":False}).get('exp')
        return self

    def id(self):
        return f"{self.ip}@{self.host}"
    
    def json(self):
        return {
            'ip': self.ip,
            'host': self.host,
            'token': self.token,
            'expiration': self.expiration,
        }
