from __future__ import annotations

import logging
from typing import cast

from django.contrib.auth.base_user import AbstractBaseUser
from django.http import HttpRequest

from allauth import app_settings as allauth_settings


logger = logging.getLogger(__name__)

# Key under which the IdP session coordinates are stored in
# ``UserSession.data``.
USERSESSION_DATA_KEY = "saml"


def _usersessions_required(feature: str) -> bool:
    if allauth_settings.USERSESSIONS_ENABLED:
        return True
    logger.warning(
        "SAML `%s` requires `allauth.usersessions` to be installed.", feature
    )
    return False


def record_saml_session(request: HttpRequest, provider, auth) -> None:
    """Remember, per local session, which IdP session it belongs to, so that
    a logout at the IdP (SLO) can be linked back to the local session(s), and
    so that per-tenant session limits can be enforced.
    """
    if not allauth_settings.USERSESSIONS_ENABLED:
        return
    from allauth.usersessions.models import UserSession

    session_key = request.session.session_key
    if not session_key:
        return
    user_session = UserSession.objects.filter(session_key=session_key).first()
    if user_session is None:
        return
    info = {
        # The ``client_id`` doubles as the tenant/organization identifier.
        "client_id": provider.app.client_id,
        "nameid": auth.get_nameid(),
        "session_index": auth.get_session_index(),
    }
    data = dict(user_session.data or {})
    data[USERSESSION_DATA_KEY] = info
    user_session.data = data
    user_session.save(update_fields=["data"])


def enforce_max_concurrent_sessions(request: HttpRequest, provider) -> None:
    """Enforce the per-tenant ``advanced.max_concurrent_sessions`` setting by
    ending the oldest sessions of the user beyond the limit. Only sessions
    established via the same tenant (``client_id``) are taken into account, so
    that logging in at one tenant never evicts sessions of another tenant.
    """
    limit = provider.app.settings.get("advanced", {}).get("max_concurrent_sessions")
    if not limit:
        return
    if not _usersessions_required("max_concurrent_sessions"):
        return
    from allauth.usersessions.models import UserSession

    client_id = provider.app.client_id
    current_key = request.session.session_key
    # Caller guarantees the user is authenticated.
    user = cast(AbstractBaseUser, request.user)
    sessions = []
    for user_session in UserSession.objects.filter(user_id=user.pk):
        if user_session.session_key != current_key:
            # NOTE: Do not purge the session of the ongoing request -- the
            # session store is only synced once the request finishes, meaning
            # a purge would wrongly consider it stale.
            if user_session.purge():
                continue
        if (
            user_session.data.get(USERSESSION_DATA_KEY, {}).get("client_id")
            != client_id
        ):
            continue
        sessions.append(user_session)
    # Keep the current session, then the most recently created ones.
    sessions.sort(
        key=lambda us: (us.session_key == current_key, us.created_at),
        reverse=True,
    )
    excess = sessions[limit:]
    if not excess:
        return
    from allauth.usersessions.adapter import get_adapter

    logger.info(
        "Ending %d SAML session(s) of user %s exceeding max_concurrent_sessions=%d",
        len(excess),
        user.pk,
        limit,
    )
    get_adapter().end_sessions(excess)


def logout_saml_sessions(
    request: HttpRequest, provider, nameid, session_indexes=()
) -> int:
    """End all local sessions (other than the one of the current request, which
    is handled by the regular logout flow) that belong to the given IdP
    session. Returns the number of sessions ended.
    """
    if not nameid:
        return 0
    if not _usersessions_required("SLO session cleanup"):
        return 0
    from allauth.usersessions.models import UserSession

    current_key = request.session.session_key
    candidates = UserSession.objects.filter(
        **{
            f"data__{USERSESSION_DATA_KEY}__client_id": provider.app.client_id,
            f"data__{USERSESSION_DATA_KEY}__nameid": nameid,
        }
    )
    sessions_to_end = []
    for user_session in candidates.iterator():
        if user_session.session_key == current_key:
            continue
        saml = user_session.data.get(USERSESSION_DATA_KEY, {})
        if session_indexes and saml.get("session_index") not in session_indexes:
            continue
        sessions_to_end.append(user_session)
    if sessions_to_end:
        from allauth.usersessions.adapter import get_adapter

        get_adapter().end_sessions(sessions_to_end)
    return len(sessions_to_end)
