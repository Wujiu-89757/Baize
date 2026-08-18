"""文件管理接口（文档 7.4）。"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user, get_db
from app.core.errors import NotFoundError
from app.schemas.api import FileDetail, Page
from app.services import audit, files

router = APIRouter(prefix="/api/v1/files", tags=["files"])


@router.post("", response_model=FileDetail)
def upload(request: Request, db: Session = Depends(get_db),
           user=Depends(get_current_user),
           file: UploadFile = File(...)):
    # 同步 def：由 FastAPI 放到线程池执行，避免大文件读写/哈希阻塞事件循环
    row, deduplicated = files.save_upload(db, file.file, file.filename or "unknown.pcap",
                                          user.id, user.username, file.content_type or "")
    audit.log_audit(db, user_id=user.id, username=user.username, action="file.upload",
                    target_type="file", target_id=row.id,
                    detail={"name": row.original_name, "sha256": row.sha256,
                            "size": row.size_bytes, "deduplicated": deduplicated},
                    ip=client_ip(request))
    db.commit()
    out = files.file_to_dict(row)
    out["deduplicated"] = deduplicated
    return out


@router.get("", response_model=Page)
def list_files(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=200),
               status: str = "", q: str = "",
               db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows, total = files.list_files(db, page, page_size, status, q)
    return Page(total=total, items=[files.file_to_dict(r) for r in rows],
                page=page, page_size=page_size)


@router.get("/{file_id}", response_model=FileDetail)
def get_file(file_id: str, db: Session = Depends(get_db),
             user=Depends(get_current_user)):
    return files.file_to_dict(files.get_file(db, file_id))


@router.get("/{file_id}/download")
def download(file_id: str, db: Session = Depends(get_db),
             user=Depends(get_current_user)):
    row = files.get_file(db, file_id)
    if not os.path.exists(row.storage_path):
        raise NotFoundError("文件已从磁盘清理")
    audit.log_audit(db, user_id=user.id, username=user.username, action="file.download",
                    target_type="file", target_id=row.id)
    db.commit()
    return FileResponse(row.storage_path, filename=row.original_name)


@router.delete("/{file_id}", response_model=FileDetail)
def delete_file(file_id: str, db: Session = Depends(get_db),
                user=Depends(get_current_user)):
    row = files.soft_delete(db, file_id)
    audit.log_audit(db, user_id=user.id, username=user.username, action="file.delete",
                    target_type="file", target_id=file_id)
    db.commit()
    return files.file_to_dict(row)
