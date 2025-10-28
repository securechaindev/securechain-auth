from datetime import datetime

from app.utils import JSONEncoder


def test_json_encoder_encode_dict():
    encoder = JSONEncoder()
    data = {"key": "value", "number": 42}
    result = encoder.encode(data)

    assert result == data


def test_json_encoder_encode_with_datetime():
    encoder = JSONEncoder()
    now = datetime(2024, 1, 15, 10, 30, 0)
    data = {"timestamp": now}

    result = encoder.encode(data)
    assert result["timestamp"] == "2024-01-15T10:30:00"


def test_json_encoder_encode_nested_with_datetime():
    encoder = JSONEncoder()
    now = datetime(2024, 1, 15, 10, 30, 0)

    data = {
        "user": {
            "created_at": now,
            "name": "Test User"
        }
    }

    result = encoder.encode(data)
    assert result["user"]["created_at"] == "2024-01-15T10:30:00"
    assert result["user"]["name"] == "Test User"
