from datetime import datetime
from json import dumps, loads
from typing import Any

from bson import ObjectId


class JSONEncoder:
    @staticmethod
    def default(o: Any) -> Any:
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")

    def encode(self, raw_response: dict[str, Any]) -> dict[str, Any]:
        return loads(dumps(raw_response, default=self.default))
