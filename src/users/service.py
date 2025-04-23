import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from jose import jwt

from .utils import get_password_hash
from .schemas import RefreshSessionUpdate, UserCreate, User, Token, UserCreateDB, RefreshSessionCreate, UserUpdate, UserUpdateDB
from .models import UserModel, RefreshSessionModel
from .dao import UserDAO, RefreshSessionDAO
from ..exceptions import InvalidTokenException, TokenExpiredException, InvalidCredentialsException
from ..database import async_session_maker
from ..config import settings


class AuthService:
    @classmethod
    async def create_token(cls, user_id: uuid.UUID) -> Token:
        access_token = cls._create_access_token(user_id)
        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_token = cls._create_refresh_token()

        async with async_session_maker() as session:
            await RefreshSessionDAO.add(
                session,
                RefreshSessionCreate(
                    user_id=user_id,
                    refresh_token=refresh_token,
                    expires_in=int(refresh_token_expires.total_seconds())
                )
            )
            await session.commit()
        return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")

    @classmethod
    async def logout(cls, token: uuid.UUID) -> None:
        async with async_session_maker() as session:
            refresh_session = await RefreshSessionDAO.find_one_or_none(session, RefreshSessionModel.refresh_token == token)
            if refresh_session:
                await RefreshSessionDAO.delete(session, id=refresh_session.id)
            await session.commit()

    @classmethod
    async def refresh_token(cls, token: uuid.UUID) -> Token:
        async with async_session_maker() as session:
            refresh_session = await RefreshSessionDAO.find_one_or_none(
                session,
                RefreshSessionModel.refresh_token == token
            )

            if refresh_session is None:
                raise InvalidTokenException

            if datetime.now(timezone.utc) >= refresh_session.created_at + timedelta(seconds=refresh_session.expires_in):
                await RefreshSessionDAO.delete(session=session, id=refresh_session.id)
                raise TokenExpiredException

            user = await UserDAO.find_one_or_none(session, id=refresh_session.user_id)
            if user is None:
                raise InvalidTokenException

            access_token = cls._create_access_token(user.id)
            refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            refresh_token = cls._create_refresh_token()

            await RefreshSessionDAO.update(
                session,
                RefreshSessionModel.id == refresh_session.id,
                obj_in=RefreshSessionUpdate(
                    refresh_token=refresh_token,
                    expires_in=int(refresh_token_expires.total_seconds()),
                    user_id=None
                )
            )
            await session.commit()
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    @classmethod
    async def authenticate_user(cls, email: str, password: str) -> User | None:
        async with async_session_maker() as session:
            db_user = await UserDAO.find_one_or_none(session, email=email)
        if not db_user:
            raise InvalidCredentialsException
        return User.model_validate(db_user)


    @classmethod
    async def abort_all_sessions(cls, user_id: uuid.UUID):
        async with async_session_maker() as session:
            await RefreshSessionDAO.delete(session, RefreshSessionModel.user_id == user_id)
            await session.commit()

    @classmethod
    def _create_access_token(cls, user_id: uuid.UUID) -> str:
        to_encode = {
            "sub": str(user_id),
            "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        }
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return f'Bearer {encoded_jwt}'

    @classmethod
    def _create_refresh_token(cls) -> uuid.UUID:
        return uuid.uuid4()


class UserService:
    @classmethod
    async def register_new_user(cls, user: UserCreate) -> User:
        async with async_session_maker() as session:
            user_exist = await UserDAO.find_one_or_none(session, email=user.email)
            if user_exist:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT, detail="User already exists"
                )

            user.is_superuser = False
            user.is_verified = False
            db_user = await UserDAO.add(
                session,
                UserCreateDB(
                    **user.model_dump(),
                    hashed_password=get_password_hash(user.password)
                )
            )
            await session.commit()

        return User.model_validate(db_user)

    @classmethod
    async def get_user(cls, user_id: uuid.UUID) -> User:
        async with async_session_maker() as session:
            db_user = await UserDAO.find_one_or_none(session, id=user_id)
        if db_user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        return User.model_validate(db_user)

    @classmethod
    async def update_user(cls, user_id: uuid.UUID, user: UserUpdate) -> UserUpdate:
        async with async_session_maker() as session:
            db_user = await UserDAO.find_one_or_none(session, UserModel.id == user_id)
            if db_user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            if user.password:
                user_in = UserUpdateDB(
                    **user.model_dump
                    (
                        exclude={'is_active', 'is_verified', 'is_superuser'},
                        exclude_unset=True
                    ),
                    hashed_password=get_password_hash(user.password)
                )
            else:
                user_in = UserUpdateDB(**user.model_dump())

            user_update = await UserDAO.update(session, UserModel.id == user_id, obj_in=user_in)
            await session.commit()
            return UserUpdate.model_validate(user_update)

    @classmethod
    async def delete_user(cls, user_id: uuid.UUID):
        async with async_session_maker() as session:
            db_user = await UserDAO.find_one_or_none(session, id=user_id)
            if db_user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            await UserDAO.update(
                session,
                UserModel.id == user_id,
                {'is_active': False}
            )
            await session.commit()

    @classmethod
    async def get_users_list(
            cls, *filter,
            offset: int = 0,
            limit: int = 100,
            **filter_by
    ) -> list[User] | None:
        async with async_session_maker() as session:
            db_users = await UserDAO.find_all(session, *filter, offset=offset, limit=limit, **filter_by)

        return [
            User(
                id=db_user.id,
                email=db_user.email,
                fio=db_user.fio,
                is_active=db_user.is_active,
                is_superuser=db_user.is_superuser,
                is_verified=db_user.is_verified
            )
            for db_user
            in db_users
        ]

    @classmethod
    async def update_user_from_superuser(cls, user_id: uuid.UUID, user: UserUpdate) -> UserUpdate:
        async with async_session_maker() as session:
            db_user = await UserDAO.find_one_or_none(session, UserModel.id == user_id)
            if db_user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            user_in = UserUpdateDB(**user.model_dump(exclude_unset=True))
            user_update = await UserDAO.update(
                session,
                UserModel.id == user_id,
                obj_in=user_in
            )
            await session.commit()
            return user_update

    @classmethod
    async def delete_user_from_superuser(cls, user_id: uuid.UUID):
        async with async_session_maker() as session:
            await UserDAO.delete(session, UserModel.id == user_id)
            await session.commit()
