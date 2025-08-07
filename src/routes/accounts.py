from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from sqlalchemy.orm import joinedload
from starlette.responses import JSONResponse

from exceptions.security import TokenExpiredError, InvalidTokenError
from schemas.accounts import UserRegistrationResponseBase, UserRegistrationRequestBase, UserActivationRequestBase, \
    UserPasswordResetRequestBase, UserPasswordResetCompletion, UserLoginRequestBase, RefreshTokenRequestBase
from security.passwords import hash_password, verify_password

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseBase, status_code=201)
async def register(
        user_data: UserRegistrationRequestBase,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    db_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    if db_user.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )

    try:
        hashed = hash_password(user_data.password)
        result = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        group = result.scalar_one_or_none()
        new_user = UserModel(
            email=user_data.email,
            _hashed_password=hashed,
            group_id=group.id
        )

        activation_token_value = jwt_manager.create_activation_token({"sub": new_user.email})
        activation_token = ActivationTokenModel(
            user=new_user,
            token=activation_token_value,
            expires_at=datetime.utcnow() + timedelta(days=1)
        )

        db.add_all([new_user, activation_token])
        await db.commit()
        await db.refresh(new_user)
        return new_user

    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/")
async def activate(
        user_data: UserActivationRequestBase,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    result_user = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == user_data.email)
    )
    user = result_user.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User does not exist.")
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    try:
        jwt_manager.verify_activation_token_or_raise(user_data.token)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if not user.activation_token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    expires_at = user.activation_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    user.is_active = True
    db.add(user)
    if user.activation_token:
        await db.delete(user.activation_token)
    await db.commit()
    await db.refresh(user)
    return JSONResponse({"message": "User account activated successfully."})


@router.post("/password-reset/request/")
async def password_reset_request(
        user_data: UserPasswordResetRequestBase,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    db_user = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == user_data.email)
    )
    user = db_user.scalar_one_or_none()
    if not user or not user.is_active:
        return JSONResponse({"message": "If you are registered, you will receive an email with instructions."})
    if user.password_reset_token:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
    password_token_value = jwt_manager.create_password_reset_token({"sub": user.email})
    password_reset_token = PasswordResetTokenModel(
        user=user,
        token=password_token_value,
        expires_at=datetime.utcnow() + timedelta(days=1)
    )
    db.add(password_reset_token)
    await db.commit()
    await db.refresh(user)
    return JSONResponse({"message": "If you are registered, you will receive an email with instructions."})


@router.post("/reset-password/complete/")
async def password_reset_completion(
        user_data: UserPasswordResetCompletion,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    db_user = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == user_data.email)
    )
    user = db_user.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        jwt_manager.verify_password_reset_token_or_raise(user_data.token)
    except (TokenExpiredError, InvalidTokenError):
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    if not user.password_reset_token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    expires_at = user.password_reset_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        hashed = hash_password(user_data.password)
        user._hashed_password = hashed
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
        await db.refresh(user)
        return JSONResponse({"message": "Password reset successfully."})

    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/")
async def user_login(
        user_data: UserLoginRequestBase,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    db_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = db_user.scalar_one_or_none()
    if not user or not verify_password(user_data.password, user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token_value = jwt_manager.create_access_token({"user_id": user.id, "email": user.email})
        refresh_token_value = jwt_manager.create_refresh_token({"user_id": user.id, "email": user.email})
        refresh_token = RefreshTokenModel(
            user=user,
            token=refresh_token_value,
            expires_at=datetime.utcnow() + timedelta(minutes=60 * 24 * 7)
        )
        db.add(refresh_token)
        await db.commit()
        await db.refresh(refresh_token)
        return JSONResponse(
            status_code=201,
            content={
                "access_token": access_token_value,
                "refresh_token": refresh_token.token,
                "token_type": "bearer"
            }
        )
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/")
async def refresh_token(
        refresh_token_data: RefreshTokenRequestBase,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        jwt_manager.verify_refresh_token_or_raise(refresh_token_data.refresh_token)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(status_code=400, detail="Token has expired.")
    result = await db.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == refresh_token_data.refresh_token)
    )
    refresh_token = result.scalar_one_or_none()
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    user_result = await db.execute(select(UserModel).where(UserModel.id == refresh_token.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    access_token = jwt_manager.create_access_token({"user_id": user.id, "email": user.email})
    return JSONResponse({"access_token": access_token})
