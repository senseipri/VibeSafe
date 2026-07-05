import io
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import BackgroundTasks, HTTPException, UploadFile

db_stub = types.ModuleType("vibesafe.api.db")
db_stub.get_db = lambda: None
sys.modules.setdefault("vibesafe.api.db", db_stub)

models_stub = types.ModuleType("vibesafe.api.models")
models_stub.Scan = type("Scan", (), {})
models_stub.ScanFinding = type("ScanFinding", (), {})
sys.modules.setdefault("vibesafe.api.models", models_stub)

from vibesafe.api.routes import scan as scan_routes

pytestmark = pytest.mark.anyio


class _TrackingTempFile:
    def __init__(self) -> None:
        self.name = "tracked-upload.zip"
        self.closed = False
        self.buffer = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def write(self, chunk: bytes) -> None:
        self.buffer.extend(chunk)

    def close(self) -> None:
        self.closed = True


async def test_scan_upload_unlinks_only_after_temp_file_is_closed(monkeypatch):
    upload = UploadFile(filename="repo.zip", file=io.BytesIO(b"PK\x03\x04" + b"x" * 32))
    background_tasks = BackgroundTasks()
    db = AsyncMock()
    tracking_file = _TrackingTempFile()
    unlink_calls: list[Path] = []

    monkeypatch.setattr(scan_routes.tempfile, "NamedTemporaryFile", lambda **kwargs: tracking_file)
    monkeypatch.setattr(scan_routes, "MAX_UPLOAD_ZIP_BYTES", 8)

    def _capture_unlink(path: Path) -> None:
        assert tracking_file.closed is True
        unlink_calls.append(path)

    monkeypatch.setattr(scan_routes, "_safe_unlink", _capture_unlink)

    with pytest.raises(HTTPException) as exc_info:
        await scan_routes.scan_upload(background_tasks=background_tasks, file=upload, db=db)

    assert exc_info.value.status_code == 413
    assert exc_info.value.detail == "ZIP file exceeds maximum size of 250MB."
    assert unlink_calls == [Path(tracking_file.name)]
    assert tracking_file.closed is True
    assert upload.file.closed is True
    db.commit.assert_not_awaited()


async def test_safe_unlink_swallows_permission_error_and_logs(monkeypatch):
    warning_mock = MagicMock()
    monkeypatch.setattr(scan_routes.logger, "warning", warning_mock)

    def _raise_permission_error(self, missing_ok=False):
        raise PermissionError("locked")

    monkeypatch.setattr(Path, "unlink", _raise_permission_error)

    scan_routes._safe_unlink(Path("locked-upload.zip"))

    warning_mock.assert_called_once()
