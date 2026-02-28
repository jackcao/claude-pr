from sqlalchemy.orm import Session

from app.core.security import get_password_hash, verify_password
from app.models.user import User
from app.schemas.user import UserCreate


class CRUDUser:
    def get(self, db: Session, id: int) -> User | None:
        """通过 ID 获取用户"""
        return db.query(User).filter(User.id == id).first()

    def get_by_username(self, db: Session, username: str) -> User | None:
        """通过用户名获取用户"""
        return db.query(User).filter(User.username == username).first()

    def get_by_email(self, db: Session, email: str) -> User | None:
        """通过邮箱获取用户"""
        return db.query(User).filter(User.email == email).first()

    def create(self, db: Session, obj_in: UserCreate) -> User:
        """创建新用户"""
        db_obj = User(
            username=obj_in.username,
            email=obj_in.email,
            hashed_password=get_password_hash(obj_in.password),
        )
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def authenticate(self, db: Session, username: str, password: str) -> User | None:
        """验证用户"""
        user = self.get_by_username(db, username)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user


user_crud = CRUDUser()
