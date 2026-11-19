from __future__ import annotations

import binascii
import logging
from http import HTTPStatus

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from onelogin.saml2.auth import OneLogin_Saml2_Settings
from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request

from allauth.account.adapter import get_adapter as get_account_adapter
from allauth.account.internal.decorators import login_not_required
from allauth.core.internal import httpkit
from allauth.socialaccount.helpers import (
    complete_social_login,
    render_authentication_error,
)
from allauth.socialaccount.providers.base.constants import AuthError, AuthProcess
from allauth.socialaccount.providers.base.views import BaseLoginView

from .sessions import (
    enforce_max_concurrent_sessions,
    logout_saml_sessions,
    record_saml_session,
)
from .utils import (
    build_auth,
    build_saml_config,
    decode_relay_state,
    get_acs_session,
    get_app_or_404,
    get_logout_request_nameid,
    get_logout_request_session_indexes,
    validate_logout_request_issuer,
    validate_response_issuer,
)


logger = logging.getLogger(__name__)


class SAMLViewMixin:
    def get_app(self, organization_slug):
        app = get_app_or_404(self.request, organization_slug)
        return app

    def get_provider(self, organization_slug):
        app = self.get_app(organization_slug)
        return app.get_provider(self.request)


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class ACSView(SAMLViewMixin, View):
    def dispatch(self, request: HttpRequest, organization_slug) -> HttpResponse:
        url = reverse(
            "saml_finish_acs",
            kwargs={"organization_slug": organization_slug},
        )
        response = HttpResponseRedirect(url)
        acs_session = get_acs_session(request, organization_slug)
        acs_session.store.update({"request": httpkit.serialize_request(request)})
        acs_session.save(response)
        return response


acs = ACSView.as_view()


@method_decorator(login_not_required, name="dispatch")
class FinishACSView(SAMLViewMixin, View):
    def dispatch(self, request: HttpRequest, organization_slug) -> HttpResponse:
        provider = self.get_provider(organization_slug)
        acs_session = get_acs_session(request, organization_slug)
        acs_request = None
        acs_request_data = acs_session.store.get("request")
        if acs_request_data:
            acs_request = httpkit.deserialize_request(acs_request_data, HttpRequest())
        acs_session.delete()
        if not acs_request:
            logger.error("Unable to finish login, SAML ACS session missing")
            return render_authentication_error(request, provider)

        auth = build_auth(acs_request, provider)
        error_reason = None
        errors = []
        try:
            # We're doing the check for a valid `InResponeTo` ourselves later on
            # (*) by checking if there is a matching state stashed.
            auth.process_response(request_id=None)
        except binascii.Error:
            errors = ["invalid_response"]
            error_reason = "Invalid response"
        except OneLogin_Saml2_Error as e:
            errors = ["error"]
            error_reason = str(e)
        if not errors:
            errors = auth.get_errors()
        if errors:
            # e.g. ['invalid_response']
            error_reason = auth.get_last_error_reason() or error_reason
            logger.error(
                "Error processing SAML ACS response: %s: %s"
                % (", ".join(errors), error_reason)
            )
            return render_authentication_error(
                request,
                provider,
                extra_context={
                    "saml_errors": errors,
                    "saml_last_error_reason": error_reason,
                },
            )
        if not auth.is_authenticated():
            return render_authentication_error(
                request, provider, error=AuthError.CANCELLED
            )
        if not validate_response_issuer(auth, acs_request.POST.get("SAMLResponse", "")):
            logger.error(
                "SAML response issuer does not match the IdP configured for"
                " organization '%s'",
                organization_slug,
            )
            return render_authentication_error(request, provider)
        login = provider.sociallogin_from_response(request, auth)
        # (*) If we (the SP) initiated the login, there should be a matching
        # state.
        state_id = auth.get_last_response_in_response_to()
        if state_id:
            login.state = provider.unstash_redirect_state(request, state_id)
        else:
            # IdP initiated SSO
            reject = provider.app.settings.get("advanced", {}).get(
                "reject_idp_initiated_sso", True
            )
            if reject:
                logger.error("IdP initiated SSO rejected")
                return render_authentication_error(request, provider)
            next_url = decode_relay_state(acs_request.POST.get("RelayState"))
            login.state["process"] = AuthProcess.LOGIN
            if next_url:
                login.state["next"] = next_url
        response = complete_social_login(request, login)
        if request.user.is_authenticated:
            record_saml_session(request, provider, auth)
            enforce_max_concurrent_sessions(request, provider)
        return response


finish_acs = FinishACSView.as_view()


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class SLSView(SAMLViewMixin, View):
    def dispatch(self, request: HttpRequest, organization_slug) -> HttpResponse:
        provider = self.get_provider(organization_slug)
        auth = build_auth(self.request, provider)
        should_logout = request.user.is_authenticated
        account_adapter = get_account_adapter(request)

        def force_logout() -> None:
            account_adapter.logout(request)

        redirect_to = None
        error_reason = None
        try:
            redirect_to = auth.process_slo(
                delete_session_cb=force_logout, keep_local_session=not should_logout
            )
            # We do not validate ``redirect_to``: The IdP is a trusted party,
            # when using SAML the SP is configured to trust it. Restricting its
            # SLO redirect URL with ``is_safe_url`` (which typically only allows
            # same-origin URLs) could break legitimate cross-domain redirects
            # the IdP provides, e.g. redirecting back to the IdP's own logout
            # landing page.  The python3-saml library already validates the SAML
            # response signature before returning the redirect URL.
        except OneLogin_Saml2_Error as e:
            error_reason = str(e)
        errors = auth.get_errors()
        if errors:
            error_reason = auth.get_last_error_reason() or error_reason
            logger.error(
                "Error processing SAML SLS response: %s: %s"
                % (", ".join(errors), error_reason)
            )
            resp = HttpResponse(error_reason, content_type="text/plain")
            resp.status_code = HTTPStatus.BAD_REQUEST
            return resp
        saml_request = request.GET.get("SAMLRequest")
        if saml_request:
            # The IdP initiated a logout: beyond the session of the current
            # request (handled above), end all other local sessions belonging
            # to this IdP session.
            logout_request = OneLogin_Saml2_Logout_Request(
                auth.get_settings(), saml_request
            )
            if not validate_logout_request_issuer(auth, logout_request):
                logger.error(
                    "SAML LogoutRequest issuer does not match the IdP configured"
                    " for organization '%s'",
                    organization_slug,
                )
                resp = HttpResponse("invalid_issuer", content_type="text/plain")
                resp.status_code = HTTPStatus.BAD_REQUEST
                return resp
            ended = logout_saml_sessions(
                request,
                provider,
                get_logout_request_nameid(logout_request),
                get_logout_request_session_indexes(logout_request),
            )
            if ended:
                logger.info("SAML SLO ended %d additional local session(s)", ended)
        if not redirect_to:
            redirect_to = account_adapter.get_logout_redirect_url(request)
        return HttpResponseRedirect(redirect_to)


sls = SLSView.as_view()


@method_decorator(login_not_required, name="dispatch")
class MetadataView(SAMLViewMixin, View):
    def dispatch(self, request: HttpRequest, organization_slug) -> HttpResponse:
        provider = self.get_provider(organization_slug)
        config = build_saml_config(
            self.request, provider.app.settings, organization_slug
        )
        saml_settings = OneLogin_Saml2_Settings(
            settings=config, sp_validation_only=True
        )
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)

        if len(errors) > 0:
            resp = JsonResponse({"errors": errors})
            resp.status_code = HTTPStatus.INTERNAL_SERVER_ERROR
            return resp

        return HttpResponse(content=metadata, content_type="text/xml")


metadata = MetadataView.as_view()


@method_decorator(login_not_required, name="dispatch")
class LoginView(SAMLViewMixin, BaseLoginView):
    def get_provider(self):
        app = self.get_app(self.kwargs["organization_slug"])
        return app.get_provider(self.request)


login = LoginView.as_view()
