"""文件服务（文档 7.x）：上传、哈希、magic 探测、去重、软删除、格式校验。"""
from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Optional

from sqlalchemy.orm import Session

from app.analysis.parsing.base import probe_format
from app.core.config import settings
from app.core.errors import NotFoundError, ValidationError
from app.models import UploadedFile


def _sha256_stream(fh: BinaryIO, chunk: int = 1 << 20) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    while True:
        block = fh.read(chunk)
        if not block:
            break
        h.update(block)
        size += len(block)
    return h.hexdigest(), size


def save_upload(session: Session, stream: BinaryIO, original_name: str,
                uploader_id: Optional[int], uploader_name: str, mime: str = "") -> tuple[UploadedFile, bool]:
    """校验 → 临时写入 → SHA-256 → magic 探测 → 去重 → 入库。

    返回 (记录, 本次是否被去重)。重复上传时返回已有记录且 deduplicated=True，
    但**不修改原记录**（原记录不被打上 duplicate_of，避免把历史文件永久标记为"重复"）。
    """
    name = Path(original_name).name  # 清洗路径，防穿越
    ext = Path(name).suffix.lower()
    if ext not in settings.allowed_extensions:
        raise ValidationError(
            f"不支持的文件类型 {ext!r}，仅允许: {', '.join(settings.allowed_extensions)}")

    tmp_dir = settings.upload_dir
    tmp_path = tmp_dir / f"tmp-{uuid.uuid4().hex}"
    size = 0
    try:
        with open(tmp_path, "wb") as out:
            while True:
                block = stream.read(1 << 20)
                if not block:
                    break
                size += len(block)
                if size > settings.max_upload_size:
                    raise ValidationError(f"文件超过大小限制 {settings.max_upload_size // (1 << 20)} MB")
                out.write(block)
        sha256 = _sha256_stream(open(tmp_path, "rb"))[0]

        fmt = probe_format(str(tmp_path))
        if fmt == "unknown":
            raise ValidationError("文件内容不是合法的 pcap/pcapng（magic 校验失败）")

        # 去重：同一哈希已有未删除文件 → 不落新记录，也不污染原记录
        dup = (session.query(UploadedFile)
               .filter(UploadedFile.sha256 == sha256, UploadedFile.deleted == False).first())  # noqa: E712
        if dup is not None:
            os.unlink(tmp_path)
            return dup, True

        fid = uuid.uuid4().hex
        stored_name = f"{fid}.{fmt}"
        storage = settings.storage_dir / stored_name
        os.replace(tmp_path, storage)

        row = UploadedFile(
            id=fid, original_name=name, stored_name=stored_name, storage_path=str(storage),
            sha256=sha256, size_bytes=size, format=fmt, status="uploaded",
            mime=mime, uploader_id=uploader_id, uploader_name=uploader_name or "-",
        )
        session.add(row)
        session.flush()
        return row, False
    finally:
        if tmp_path.exists():
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def get_file(session: Session, file_id: str) -> UploadedFile:
    row = session.get(UploadedFile, file_id)
    if row is None or row.deleted:
        raise NotFoundError(f"文件不存在: {file_id}")
    return row


def list_files(session: Session, page: int = 1, page_size: int = 20,
               status: str = "", q: str = "") -> tuple[list[UploadedFile], int]:
    query = session.query(UploadedFile).filter(UploadedFile.deleted == False)  # noqa: E712
    if status:
        query = query.filter(UploadedFile.status == status)
    if q:
        query = query.filter(UploadedFile.original_name.contains(q) | UploadedFile.sha256.startswith(q))
    total = query.count()
    rows = query.order_by(UploadedFile.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return rows, total


def soft_delete(session: Session, file_id: str) -> UploadedFile:
    row = get_file(session, file_id)
    row.deleted = True
    row.deleted_at = datetime.now(timezone.utc)
    row.status = "deleted"
    session.flush()
    return row


def file_to_dict(row: UploadedFile) -> dict:
    return {
        "id": row.id, "original_name": row.original_name, "size_bytes": row.size_bytes,
        "sha256": row.sha256, "format": row.format, "status": row.status,
        "uploader_name": row.uploader_name, "created_at": row.created_at,
        "error_message": row.error_message, "duplicate_of": row.duplicate_of,
        "storage_path": row.storage_path,
    }
