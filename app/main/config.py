# ------------------------------------------------------------------------------------------------ #
# Copyright (c) 2026 Carmenda. All rights reserved.                                                #
# This program is distributed under the terms of the GNU General Public License: GPL-3.0-or-later  #
# ------------------------------------------------------------------------------------------------ #

"""Centralised application configuration via pydantic-settings."""

import os
import sys
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


def _detect_environment() -> tuple[str, Path, str, str]:
    """Get proper app base, folder & file paths based on the current environment."""
    if os.environ.get('DOCKER_ENV') == 'true':
        return 'docker', Path('/app'), '/app/data/input', '/app/data/output'
    if getattr(sys, 'frozen', False):
        base = Path(getattr(sys, '_MEIPASS', '.')) / 'app'
        return 'frozen', base, str(base / 'data' / 'input'), str(base / 'data' / 'output')
    return 'development', Path(__file__).parent.parent, 'data/input', 'data/output'


environment, app_base, input_folder, output_folder = _detect_environment()

app_version = (app_base / 'main' / 'VERSION').read_text().strip()


class Settings(BaseSettings):
    """Settings to configure the API."""

    app_title: str = 'carmenda-deduce-engine'
    app_version: str = app_version
    host: str = 'localhost'
    port: int = 8001
    debug: bool = False
    log_level: str = 'INFO'
    environment: str = environment
    m2m_hash: SecretStr = SecretStr('')
    data_encryption_key: SecretStr = SecretStr('')
    input_folder: str = input_folder
    output_folder: str = output_folder
    model_config = SettingsConfigDict(env_file=app_base / '.env')


settings = Settings()
