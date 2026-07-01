import pytest
import asyncio
from pathlib import Path


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_manifest(tmp_path, fixtures_dir):
    from vibesafe.scanner.ingest import build_manifest
    import shutil

    for f in fixtures_dir.iterdir():
        if f.is_file():
            shutil.copy(f, tmp_path / f.name)
    return build_manifest(tmp_path)
