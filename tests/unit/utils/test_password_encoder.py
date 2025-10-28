from app.utils import PasswordEncoder


def test_password_encoder_hash():
    encoder = PasswordEncoder()
    password = "TestPassword123!"
    
    hashed = encoder.hash(password)
    
    assert hashed != password
    assert hashed.startswith("$2b$")


def test_password_encoder_verify_correct_password():
    encoder = PasswordEncoder()
    password = "TestPassword123!"
    hashed = encoder.hash(password)
    
    result = encoder.verify(password, hashed)
    
    assert result is True


def test_password_encoder_verify_incorrect_password():
    encoder = PasswordEncoder()
    password = "TestPassword123!"
    hashed = encoder.hash(password)
    
    result = encoder.verify("WrongPassword456!", hashed)
    
    assert result is False
