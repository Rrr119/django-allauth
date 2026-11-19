import base64
import zlib
from http import HTTPStatus
from unittest.mock import patch

from django.test.client import Client
from django.urls import reverse

import pytest

from allauth.socialaccount.internal import statekit


@pytest.fixture
def client():
    client = Client(HTTP_HOST="example.com")
    return client


@pytest.fixture
def saml_settings(settings):
    settings.SOCIALACCOUNT_PROVIDERS = {
        "saml": {
            "APPS": [
                {
                    "client_id": "org",
                    "provider_id": "urn:dev-123.us.auth0.com",
                    "settings": {
                        "attribute_mapping": {
                            "uid": "http://schemas.auth0.com/clientID",
                            "email_verified": "http://schemas.auth0.com/email_verified",
                            "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                        },
                        "idp": {
                            "name": "Test IdP",
                            "entity_id": "urn:dev-123.us.auth0.com",
                            "sso_url": "https://dev-123.us.auth0.com/samlp/456",
                            "slo_url": "https://dev-123.us.auth0.com/samlp/456",
                            "x509cert": "",
                        },
                        "advanced": {
                            "strict": False,
                        },
                    },
                }
            ]
        }
    }


@pytest.fixture
def acs_saml_response_factory():
    def factory(in_response_to=None):
        xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id123"  InResponseTo="{in_response_to or ""}"  Version="2.0" IssueInstant="2023-07-08T08:24:14.141Z"  Destination="http://example.com/accounts/saml/org/acs/">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:dev-123.us.auth0.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="id321" IssueInstant="2023-07-08T08:24:14.094Z">
    <saml:Issuer>urn:dev-123.us.auth0.com</saml:Issuer>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <SignedInfo>
        <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <Reference URI="#id321">
          <Transforms>
            <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </Transforms>
          <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <DigestValue>A321
          </DigestValue>
        </Reference>
      </SignedInfo>
      <SignatureValue>MTIz
      </SignatureValue>
      <KeyInfo>
        <X509Data>
          <X509Certificate>MIIDHTCC...
          </X509Certificate>
        </X509Data>
      </KeyInfo>
    </Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">google-oauth2|108204123456789
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2123-07-08T09:24:14.094Z" Recipient="http://example.com/accounts/saml/org/acs/" InResponseTo="id321"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2023-07-08T08:24:14.094Z" NotOnOrAfter="2123-07-08T09:24:14.094Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://example.com/accounts/saml/org/metadata/</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2023-07-08T08:24:14.094Z" SessionIndex="_qPrYdL0O8w3vdb8eCEY5ZtHe76LA8-JU">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">google-oauth2|108204123456789
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">john.doe@email.org
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">John
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">John
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">john.doe@email.org
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/identities/default/provider" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">google-oauth2
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/identities/default/connection" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">google-oauth2
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/identities/default/isSocial" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:boolean">true
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/clientID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">dummysamluid
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/created_at" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:anyType">Wed Jun 28 2023 17:53:49 GMT+0000 (Coordinated Universal Time)
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/email_verified" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:boolean">true
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/locale" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">en
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/nickname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">john.doe
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/picture" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">https://lh3.googleusercontent.com/a/AAcHTtfZ0fEyL3BKP1Hk2v1bNwpJd6ckIeo6jSExlkVjMXaIpsY=s96-c
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/updated_at" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:anyType">Sat Jul 08 2023 06:13:07 GMT+0000 (Coordinated Universal Time)
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
         <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">view-profile</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="Role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
         <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">manage-account-links</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
"""
        return base64.b64encode(xml.encode("utf8")).decode("utf8")

    return factory


@pytest.fixture
def sls_saml_request():
    xml = (
        '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr1" Version="2.0"'
        ' IssueInstant="2023-07-08T08:24:14.141Z">'
        "<saml:Issuer>urn:dev-123.us.auth0.com</saml:Issuer>"
        "<saml:NameID>google-oauth2|108204123456789</saml:NameID>"
        "</samlp:LogoutRequest>"
    )
    return base64.b64encode(xml.encode("utf8")).decode("utf8")


@pytest.fixture
def mocked_signature_validation():
    with patch("onelogin.saml2.utils.OneLogin_Saml2_Utils.validate_sign") as mock:
        mock.return_value = True
        yield


def _tenant_app(organization_slug, idp_entity_id, idp_base_url, **advanced):
    return {
        "client_id": organization_slug,
        "provider_id": idp_entity_id,
        "settings": {
            "attribute_mapping": {
                "uid": "http://schemas.auth0.com/clientID",
                "email_verified": "http://schemas.auth0.com/email_verified",
                "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            },
            "idp": {
                "entity_id": idp_entity_id,
                "sso_url": f"{idp_base_url}/sso",
                "slo_url": f"{idp_base_url}/slo",
                "x509cert": "",
            },
            "advanced": {"strict": False, **advanced},
        },
    }


@pytest.fixture
def multi_tenant_saml_settings(settings):
    """Two tenants (orga, orgb), each hooked up to their own IdP."""
    settings.SOCIALACCOUNT_PROVIDERS = {
        "saml": {
            "APPS": [
                _tenant_app("orga", "urn:idp-a", "https://idp-a.example.com"),
                _tenant_app("orgb", "urn:idp-b", "https://idp-b.example.com"),
            ]
        }
    }


SAML_RESPONSE_TEMPLATE = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id123"  InResponseTo="{in_response_to}"  Version="2.0" IssueInstant="2023-07-08T08:24:14.141Z"  Destination="http://example.com/accounts/saml/{org}/acs/">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="id321" IssueInstant="2023-07-08T08:24:14.094Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <SignedInfo>
        <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <Reference URI="#id321">
          <Transforms>
            <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </Transforms>
          <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <DigestValue>A321
          </DigestValue>
        </Reference>
      </SignedInfo>
      <SignatureValue>MTIz
      </SignatureValue>
    </Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{nameid}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2123-07-08T09:24:14.094Z" Recipient="http://example.com/accounts/saml/{org}/acs/" InResponseTo="id321"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2023-07-08T08:24:14.094Z" NotOnOrAfter="2123-07-08T09:24:14.094Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://example.com/accounts/saml/{org}/metadata/</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2023-07-08T08:24:14.094Z" SessionIndex="{session_index}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">{email}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/clientID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:string">{uid}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.auth0.com/email_verified" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue xsi:type="xs:boolean">true</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
"""

SAML_LOGOUT_REQUEST_TEMPLATE = (
    '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
    ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr1" Version="2.0"'
    ' IssueInstant="2023-07-08T08:24:14.141Z"'
    ' Destination="http://example.com/accounts/saml/{org}/sls/">'
    "<saml:Issuer>{issuer}</saml:Issuer>"
    '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"'
    ">{nameid}</saml:NameID>"
    "{session_index_xml}"
    "</samlp:LogoutRequest>"
)


class LocalSamlIdP:
    """A minimal, in-test SAML IdP, used to drive login, logout (SLO) and
    re-login flows against the SP endpoints."""

    def __init__(self, entity_id):
        self.entity_id = entity_id

    def build_response(
        self,
        org,
        *,
        uid,
        email,
        nameid,
        session_index="_idx1",
        in_response_to="",
    ):
        xml = SAML_RESPONSE_TEMPLATE.format(
            org=org,
            issuer=self.entity_id,
            uid=uid,
            email=email,
            nameid=nameid,
            session_index=session_index,
            in_response_to=in_response_to,
        )
        return base64.b64encode(xml.encode("utf8")).decode("utf8")

    def build_logout_request(self, org, *, nameid, session_index=None, deflate=True):
        session_index_xml = (
            f"<samlp:SessionIndex>{session_index}</samlp:SessionIndex>"
            if session_index
            else ""
        )
        xml = SAML_LOGOUT_REQUEST_TEMPLATE.format(
            org=org,
            issuer=self.entity_id,
            nameid=nameid,
            session_index_xml=session_index_xml,
        )
        if deflate:
            # HTTP-Redirect binding: raw DEFLATE, then base64.
            return base64.b64encode(zlib.compress(xml.encode("utf8"))[2:-4]).decode(
                "utf8"
            )
        return base64.b64encode(xml.encode("utf8")).decode("utf8")

    def initiate_login(self, client, org, *, process="login"):
        """Initiates an SP-initiated login. Returns the state ID
        (``InResponseTo``) the IdP is expected to respond to."""
        login_url = reverse("saml_login", kwargs={"organization_slug": org})
        if process != "login":
            login_url += f"?process={process}"
        resp = client.post(login_url)
        assert resp.status_code == HTTPStatus.FOUND
        # Redirected to the IdP for authentication.
        assert resp["location"].startswith("http")
        return list(client.session[statekit.STATES_SESSION_KEY].keys())[-1]

    def complete_login(self, client, org, state_id=None, **response_kwargs):
        """Posts the SAML response for an initiated login to the ACS
        endpoint. Returns the final response of the ACS finish endpoint."""
        if state_id is None:
            state_id = list(client.session[statekit.STATES_SESSION_KEY].keys())[-1]
        saml_response = self.build_response(
            org, in_response_to=state_id, **response_kwargs
        )
        resp = client.post(
            reverse("saml_acs", kwargs={"organization_slug": org}),
            data={"SAMLResponse": saml_response},
        )
        assert resp.status_code == HTTPStatus.FOUND
        return client.get(resp["location"])

    def login(self, client, org, *, process="login", **response_kwargs):
        """Runs a full SP-initiated login round trip. Returns the final
        response of the ACS finish endpoint."""
        state_id = self.initiate_login(client, org, process=process)
        return self.complete_login(client, org, state_id, **response_kwargs)

    def logout(self, client, org, *, nameid, session_index=None):
        """Sends a LogoutRequest (SLO) to the SLS endpoint."""
        saml_request = self.build_logout_request(
            org, nameid=nameid, session_index=session_index
        )
        return client.get(
            reverse("saml_sls", kwargs={"organization_slug": org}),
            data={"SAMLRequest": saml_request},
        )


@pytest.fixture
def local_idp_factory():
    return LocalSamlIdP
