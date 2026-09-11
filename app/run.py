# ------------------------------------------------------------------------------------------------ #
# Copyright (c) 2026 Carmenda. All rights reserved.                                                #
# This program is distributed under the terms of the GNU General Public License: GPL-3.0-or-later  #
# ------------------------------------------------------------------------------------------------ #

"""FastAPI base and Swagger config."""

import logging
import shutil
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import anyio
import uvicorn
from fastapi import FastAPI

from api import router
from api.utils.worker import shutdown_worker
from core.utils.logger import setup_logging
from main.config import settings

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

logger = setup_logging()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    """Build data folders at startup; on shutdown, properly cancel any running process."""
    logger.handlers = logging.getLogger('uvicorn').handlers
    logger.propagate = False

    if settings.m2m_hash.get_secret_value():
        logger.info('Starting in Gateway mode: M2M secret configured')
    else:
        logger.warning('Starting in Standalone mode: no M2M secret set')
        await anyio.Path(settings.input_folder).mkdir(parents=True, exist_ok=True)
        await anyio.Path(settings.output_folder).mkdir(parents=True, exist_ok=True)

    temp_root = Path(tempfile.gettempdir()) / 'Carmenda'
    shutil.rmtree(temp_root, ignore_errors=True)

    yield
    shutdown_worker()


app = FastAPI(
    title=settings.app_title,
    version=settings.app_version,
    lifespan=lifespan,
    swagger_ui_parameters={'defaultModelsExpandDepth': -1},
    docs_url='/docs' if settings.debug else None,
    openapi_url='/openapi.json' if settings.debug else None,
    redoc_url=None,
    openapi_tags=[{'name': 'Info'}, {'name': 'Process engine'}, {'name': 'Output'}],
)

app.include_router(router)

if __name__ == '__main__':
    uvicorn.run(
        app if settings.environment == 'frozen' else 'run:app',
        reload=settings.debug and settings.environment == 'development',
        reload_dirs=[str(Path(__file__).parent)] if settings.debug and settings.environment == 'development' else None,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )
