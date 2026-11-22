"""Custom application exceptions for LogMorph."""

from fastapi import HTTPException, status


class APIException(HTTPException):
    """Custom HTTP exception including standardized error_code."""

    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.error_code = error_code


class InvalidApiKeyException(APIException):
    """Raised when an API key is missing, malformed, inactive, or not found."""

    def __init__(
        self,
        detail: str = "Invalid or inactive API key",
        error_code: str = "INVALID_API_KEY",
    ) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            error_code=error_code,
            headers={"WWW-Authenticate": "Bearer"},
        )


class TooManyProbesException(APIException):
    """Raised when an authenticated tenant exceeds the 404 probe threshold (FIX-P15)."""

    def __init__(
        self,
        detail: str = "Too many not-found requests. Try again in 60 seconds.",
        error_code: str = "TOO_MANY_404_PROBES",
        retry_after: int = 60,
    ) -> None:
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            error_code=error_code,
            headers={"Retry-After": str(retry_after)},
        )

