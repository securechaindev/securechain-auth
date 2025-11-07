from fastapi import HTTPException, status

from app.constants import ResponseCode, ResponseMessage


class ApiKeyNameExistsException(HTTPException):
    def __init__(self, name: str):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": ResponseCode.API_KEY_NAME_EXISTS,
                "message": ResponseMessage.API_KEY_NAME_EXISTS.format(name=name),
            }
        )
