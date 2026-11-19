from http import HTTPStatus

from django.conf import settings as django_settings
from django.test.client import Client
from django.urls import reverse

import pytest

from allauth.socialaccount.models import SocialAccount
from allauth.usersessions.models import UserSession


def new_client():
    return Client(HTTP_HOST="example.com")


def get_authenticated_user_id(client):
    return client.session.get("_auth_user_id")


@pytest.fixture
def idp_a(local_idp_factory):
    return local_idp_factory("urn:idp-a")


@pytest.fixture
def idp_b(local_idp_factory):
    return local_idp_factory("urn:idp-b")


def test_login_logout_relogin(
    client,
    db,
    multi_tenant_saml_settings,
    idp_a,
    mocked_signature_validation,
):
    """Full round trip against the local IdP: login, SLO (back-channel, i.e.
    without the user's browser), re-login."""
    # Login, browser 1.
    resp = idp_a.login(
        client, "orga", uid="u1", email="u1@example.org", nameid="nameid-1"
    )
    assert resp["location"] == django_settings.LOGIN_REDIRECT_URL
    assert get_authenticated_user_id(client) is not None
    account = SocialAccount.objects.get(provider="urn:idp-a", uid="u1")
    user_session = UserSession.objects.get(user_id=account.user_id)
    assert user_session.data["saml"] == {
        "client_id": "orga",
        "nameid": "nameid-1",
        "session_index": "_idx1",
    }

    # Login, browser 2 (same IdP account).
    client2 = new_client()
    idp_a.login(client2, "orga", uid="u1", email="u1@example.org", nameid="nameid-1")
    assert UserSession.objects.filter(user_id=account.user_id).count() == 2

    # The user logs out at the IdP. The IdP propagates this via SLO, without
    # any of the user's browsers being involved.
    slo_client = new_client()
    resp = idp_a.logout(slo_client, "orga", nameid="nameid-1", session_index="_idx1")
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"].startswith("https://idp-a.example.com/slo")
    # All local sessions are gone, in both browsers.
    assert UserSession.objects.filter(user_id=account.user_id).count() == 0
    assert get_authenticated_user_id(client) is None
    assert get_authenticated_user_id(client2) is None

    # Re-login works.
    resp = idp_a.login(
        client, "orga", uid="u1", email="u1@example.org", nameid="nameid-1"
    )
    assert resp["location"] == django_settings.LOGIN_REDIRECT_URL
    assert get_authenticated_user_id(client) is not None
    assert UserSession.objects.filter(user_id=account.user_id).count() == 1


def test_cross_tenant_response_rejected(
    client,
    db,
    multi_tenant_saml_settings,
    idp_b,
    mocked_signature_validation,
):
    """Regression (cross-tenant account mixup): a SAML response issued by the
    IdP of tenant B, posted to the ACS endpoint of tenant A, must not result
    in a login."""
    resp = client.post(reverse("saml_login", kwargs={"organization_slug": "orga"}))
    assert resp.status_code == HTTPStatus.FOUND
    saml_response = idp_b.build_response(
        "orga", uid="u-b", email="u-b@example.org", nameid="nameid-b"
    )
    resp = client.post(
        reverse("saml_acs", kwargs={"organization_slug": "orga"}),
        data={"SAMLResponse": saml_response},
    )
    assert resp.status_code == HTTPStatus.FOUND
    resp = client.get(resp["location"])
    assert "socialaccount/authentication_error.html" in (t.name for t in resp.templates)
    assert get_authenticated_user_id(client) is None
    assert not SocialAccount.objects.exists()


def test_concurrent_logins_across_tenants(
    client,
    db,
    multi_tenant_saml_settings,
    idp_a,
    idp_b,
    mocked_signature_validation,
):
    """Regression (cross-tenant account mixup): when logins at two tenants are
    in flight concurrently in the same browser, each ACS must be completed
    with its own tenant's response."""
    # Initiate both logins up front, in the same browser.
    state_a = idp_a.initiate_login(client, "orga")
    state_b = idp_b.initiate_login(client, "orgb")

    # Tenant A's IdP posts back first.
    resp = idp_a.complete_login(
        client, "orga", state_a, uid="u-a", email="u-a@example.org", nameid="n-a"
    )
    assert resp["location"] == django_settings.LOGIN_REDIRECT_URL
    account_a = SocialAccount.objects.get(provider="urn:idp-a", uid="u-a")
    assert not SocialAccount.objects.filter(provider="urn:idp-b").exists()

    # Then tenant B's IdP posts back; the pending tenant B login must still
    # complete with tenant B's own response.
    resp = idp_b.complete_login(
        client, "orgb", state_b, uid="u-b", email="u-b@example.org", nameid="n-b"
    )
    assert resp["location"] == django_settings.LOGIN_REDIRECT_URL
    account_b = SocialAccount.objects.get(provider="urn:idp-b", uid="u-b")
    assert account_a.user_id != account_b.user_id


def test_slo_is_tenant_scoped(
    client,
    db,
    settings,
    multi_tenant_saml_settings,
    idp_a,
    idp_b,
    mocked_signature_validation,
):
    """Regression (cross-tenant session mixup): SLO at tenant A's IdP must not
    terminate sessions established via tenant B."""
    settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION = True
    settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True
    # The same person logs in via both tenants (auto-connected by email).
    idp_a.login(client, "orga", uid="u-a", email="me@example.org", nameid="n-a")
    client2 = new_client()
    idp_b.login(client2, "orgb", uid="u-b", email="me@example.org", nameid="n-b")
    user_id = get_authenticated_user_id(client)
    assert user_id is not None
    assert get_authenticated_user_id(client2) == user_id
    assert UserSession.objects.filter(user_id=user_id).count() == 2

    # Logout at tenant A's IdP.
    resp = idp_a.logout(new_client(), "orga", nameid="n-a")
    assert resp.status_code == HTTPStatus.FOUND
    # Tenant A session is gone, tenant B session survives.
    assert get_authenticated_user_id(client) is None
    assert get_authenticated_user_id(client2) == user_id
    remaining = UserSession.objects.get(user_id=user_id)
    assert remaining.data["saml"]["client_id"] == "orgb"


def test_slo_rejects_foreign_issuer(
    client,
    db,
    multi_tenant_saml_settings,
    idp_a,
    idp_b,
    mocked_signature_validation,
):
    """A LogoutRequest issued by tenant B's IdP must not terminate tenant A
    sessions."""
    idp_a.login(client, "orga", uid="u-a", email="u-a@example.org", nameid="n-a")
    assert get_authenticated_user_id(client) is not None
    resp = idp_b.logout(new_client(), "orga", nameid="n-a")
    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert get_authenticated_user_id(client) is not None


def test_max_concurrent_sessions(
    client,
    db,
    settings,
    multi_tenant_saml_settings,
    idp_a,
    idp_b,
    mocked_signature_validation,
):
    """The per-tenant ``max_concurrent_sessions`` setting evicts the oldest
    session(s) beyond the limit, without touching other tenants' sessions."""
    apps = settings.SOCIALACCOUNT_PROVIDERS["saml"]["APPS"]
    apps[0]["settings"]["advanced"]["max_concurrent_sessions"] = 1

    # Browser 1 logs in at tenant A.
    idp_a.login(client, "orga", uid="u1", email="u1@example.org", nameid="n1")
    account = SocialAccount.objects.get(provider="urn:idp-a", uid="u1")
    assert UserSession.objects.filter(user_id=account.user_id).count() == 1

    # Browser 2 logs in at tenant A: browser 1's session is evicted.
    client2 = new_client()
    idp_a.login(client2, "orga", uid="u1", email="u1@example.org", nameid="n1")
    assert get_authenticated_user_id(client) is None
    assert get_authenticated_user_id(client2) is not None
    assert UserSession.objects.filter(user_id=account.user_id).count() == 1

    # Logging in at tenant B does not count towards tenant A's limit.
    settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION = True
    settings.SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True
    client3 = new_client()
    idp_b.login(client3, "orgb", uid="u1-b", email="u1@example.org", nameid="n1-b")
    assert get_authenticated_user_id(client2) is not None
    assert get_authenticated_user_id(client3) is not None
    assert UserSession.objects.filter(user_id=account.user_id).count() == 2
