import secrets
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from app.config import Settings, get_settings


SERVICE_TOKEN_HEADER = "X-DDH-Service-Token"
REQUEST_ID_HEADER = "X-Request-ID"


async def require_service_token(
    settings: Annotated[
        Settings,
        Depends(get_settings),
    ],
    supplied_token: Annotated[
        str | None,
        Header(
            alias=SERVICE_TOKEN_HEADER,
            convert_underscores=False,
        ),
    ] = None,
) -> None:
    expected_token = (
        settings.service_token
        .get_secret_value()
        .strip()
    )

    received_token = (
        supplied_token.strip()
        if supplied_token is not None
        else ""
    )

    token_is_valid = (
        bool(expected_token)
        and bool(received_token)
        and secrets.compare_digest(
            received_token.encode("utf-8"),
            expected_token.encode("utf-8"),
        )
    )

    if not token_is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing service authentication token",
            headers={
                "WWW-Authenticate": "ServiceToken",
            },
        )