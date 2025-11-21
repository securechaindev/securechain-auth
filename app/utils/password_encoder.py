from bcrypt import gensalt, hashpw, checkpw


class PasswordEncoder:
    def hash(self, password: str) -> str:
        salt = gensalt()
        return hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def verify(self, password: str, hashed_pass: str) -> bool:
        return checkpw(password.encode('utf-8'), hashed_pass.encode('utf-8'))
