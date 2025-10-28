from passlib.context import CryptContext


class PasswordEncoder:
    def __init__(self):
        self.context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def hash(self, password: str) -> str:
        return self.context.hash(password)

    def verify(self, password: str, hashed_pass: str) -> bool:
        return self.context.verify(password, hashed_pass)
