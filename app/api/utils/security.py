# ------------------------------------------------------------------------------------------------ #
# Copyright (c) 2026 Carmenda. All rights reserved.                                                #
# This program is distributed under the terms of the GNU General Public License: GPL-3.0-or-later  #
# ------------------------------------------------------------------------------------------------ #

"""Machine-to-machine connection verification.

The engine verifies a shared secret on incoming requests to confirm the connection comes
from the trusted gateway. The check is only enforced when `settings.m2m_hash` is configured
(gateway mode); without a hash the engine runs standalone and the check is skipped.
"""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException

from main.config import settings

M2M_HEADER = 'X-M2M-Key'


def verify_m2m(x_m2m_key: str = Header(default='', alias=M2M_HEADER)) -> None:
    """Reject requests that do not carry the configured M2M secret (gateway mode only)."""
    m2m_hash = settings.m2m_hash.get_secret_value()

    if not m2m_hash:
        return

    if not secrets.compare_digest(x_m2m_key, m2m_hash):
        raise HTTPException(status_code=401, detail='Invalid or missing M2M key')
