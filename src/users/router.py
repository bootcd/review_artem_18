from typing import List, Optional, Any, Coroutine
import uuid

from fastapi import APIRouter, Depends, Response, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from src.users.schemas import UserUpdate
from .models import UserModel
from .schemas import UserCreate, Token, User, UserUpdate
from .service import AuthService, UserService
from .dependencies import get_current_user, get_current_superuser, get_current_active_user
from ..exceptions import InvalidCredentialsException
from ..config import settings


auth_router = APIRouter(prefix="/auth", tags=["auth"])
user_router = APIRouter(prefix="/users", tags=["user"])


@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    user: UserCreate
) -> User:
    return await UserService.register_new_user(user)


@auth_router.post("/login")
async def login(
    response: Response,
    credentials: OAuth2PasswordRequestForm = Depends()
) -> Token | dict[str, str]:
    try:
        user = await AuthService.authenticate_user(email=credentials.username, password=credentials.password)
        token = await AuthService.create_token(user.id)
        response.set_cookie(
            'access_token',
            token.access_token,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            httponly=True
        )
        response.set_cookie(
            'refresh_token',
            token.refresh_token_string,
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 30 * 24 * 60,
            httponly=True
        )
    except Exception as e:
        return {"status" : "error", "message": str(e)}

    return token


@auth_router.post("/logout")
async def logout(
    request: Request,
    response: Response,
) -> dict[str, str]:
    try:
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        await AuthService.logout(
            uuid.UUID(request.cookies.get('refresh_token'))
        )

    except Exception as e:
        return {"status" : "error", "message": str(e)}

    return {
        "status": "ok",
        "message": "Logged out successfully"
    }


@auth_router.post("/refresh")
async def refresh_token(
    request: Request,
    response: Response
) -> Token | dict[str, str]:
    try:
        new_token = await AuthService.refresh_token(
            uuid.UUID(
                request.cookies.get("refresh_token")
            )
        )

        response.set_cookie(
            'access_token',
            new_token.access_token,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            httponly=True,
        )
        response.set_cookie(
            'refresh_token',
            new_token.refresh_token_string,
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 30 * 24 * 60,
            httponly=True,
        )
    except Exception as e:
        return {"status" : "error", "message": str(e)}

    return new_token


@auth_router.post("/abort")
async def abort_all_sessions(
    response: Response,
    user: UserModel = Depends(get_current_user)
):
    try:
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        await AuthService.abort_all_sessions(user.id)
    except Exception as e:
        return {"status" : "error", "message": str(e)}

    return {
        "status": "ok",
        "message": "All sessions was aborted"
    }


@user_router.get("")
async def get_users_list(
    offset: Optional[int] = 0,
    limit: Optional[int] = 100,
) -> List[User] | None:

    return await UserService.get_users_list(offset=offset, limit=limit)



@user_router.get("/me")
async def get_current_user(
    current_user: UserModel = Depends(get_current_active_user)
) -> User:
    return await UserService.get_user(current_user.id)


@user_router.put("/me")
async def update_current_user(
    user: UserUpdate,
    current_user: UserModel = Depends(get_current_user)
) -> UserUpdate:
    return await UserService.update_user(current_user.id, user)


@user_router.delete("/me")
async def delete_current_user(
    request: Request,
    response: Response,
    current_user: UserModel = Depends(get_current_user)
):
    try:
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        await AuthService.logout(
            uuid.UUID(request.cookies.get('refresh_token'))
        )
        await UserService.delete_user(current_user.id)
    except Exception as e:
        return {"status" : "error", "message": str(e)}

    return {
        "status" : "ok",
        "message": "User status is not active already"
    }


@user_router.get("/{user_id}")
async def get_user(
    user_id: uuid.UUID,
) -> User:
    return await UserService.get_user(
        user_id=user_id
    )


@user_router.put("/{user_id}")
async def update_user(
    user_id: uuid.UUID,
    user: UserUpdate,
) -> UserUpdate:
    return await UserService.update_user_from_superuser(user_id, user)


@user_router.delete("/{user_id}")
async def delete_user(
    user_id: uuid.UUID,
):
    await UserService.delete_user_from_superuser(user_id)
    return {"message": "User was deleted"}
