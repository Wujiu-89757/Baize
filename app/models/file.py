"""上传文件模型（文档 7.x）。原始文件不可变，只保存元数据与只读引用。"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class UploadedFile(TimestampMixin, Base):
    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    original_name: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(80), unique=True)   # 随机存储名
    storage_path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    format: Mapped[str] = mapped_column(String(16), default="unknown")  # pcap / pcapng
    status: Mapped[str] = mapped_column(String(16), default="uploaded", index=True)
    mime: Mapped[str] = mapped_column(String(80), default="")
    uploader_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    uploader_name: Mapped[str] = mapped_column(String(64), default="-")
    error_message: Mapped[str] = mapped_column(Text, default="")
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    duplicate_of: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)  # 重复文件指向
