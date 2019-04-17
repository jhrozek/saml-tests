#!/usr/bin/python3

import argparse
import logging
import urllib.parse

import requests
from bs4 import BeautifulSoup


# Exceptions
class SamlError(Exception):
    def __init__(self, msg, expected=None, got=None):
        self.msg = msg
        self.expected = expected
        self.got = got
        self._base_msg = "Saml Error"

    def __str__(self):
        str_exc = f"{self._base_msg}: {self.msg}"
        if self.expected and self.got:
            str_exc += f": expected {self.expected} but received {self.got}"
        return str_exc


class NoCredentialsError(SamlError):
    def __init__(self):
        pass

    def __str__(self):
        return "No credentials provided"


class SamlFlowError(SamlError):
    def __init__(self, got_code, expected_code=200):
        self.got_code = got_code
        self.expected_code = expected_code

    def __str__(self):
        return f"Expected HTTP code {self.expected_code} "\
                "but received {self.got_code}"


class AuthnRequestError(SamlError):
    def __init__(self, msg, expected=None, got=None):
        super(AuthnRequestError, self).__init__(msg, expected, got)
        self._base_msg = "Malformed AuthnRequest"


class SamlResponseError(SamlError):
    def __init__(self, msg, expected=None, got=None):
        super(SamlResponseError, self).__init__(msg, expected, got)
        self._base_msg = "Malformed SamlResponse"


# Utility functions
def get_location_from_redirect(redirect):
    if redirect.status_code != 303:
        raise SamlError("reply not a redirect",
                        "303", str(redirect.status_code))
    return redirect.headers.get('Location')


def same_normalized_url(orig, received):
    orig_normalized = urllib.parse.urlunparse(
                                    urllib.parse.urlparse(orig))
    received_normalized = urllib.parse.urlunparse(
                                    urllib.parse.urlparse(orig))
    logging.debug(f"Arrived at {received_normalized}")
    return orig_normalized == received_normalized


# Classes representing the Authn SP Request and the SAML IDP response
# For generic SP and IDP
class AuthnRequest(object):
    def __init__(self, resource, idp_url):
        # See SAML tech overview 5.1.2: SP-Initiated SSO, step #2
        self.saml_request = None
        self.relay_state = None
        # the resource is not part of the AuthnRequest, but we need to
        # tell the IdP where to return as part of the request
        self.resource = resource
        # the IdP name is also not part of the request, but the auth
        # request needs to redirect to the IDP, so it also makes sense
        # to store it here
        self.idp_name = urllib.parse.urlparse(idp_url).hostname

    def _check_idp_redirect_from_reply(self, idp_redirect):
        "Generic AuthnRequest checker"
        location = get_location_from_redirect(idp_redirect)
        if location is None:
            raise AuthnRequestError("No Location found in mellon redirect")

        parsed_loc = urllib.parse.urlparse(location)
        if parsed_loc.hostname != self.idp_name:
            raise AuthnRequestError("AuthnRequest does not redirect to IDP",
                                    self.idp_name,
                                    parsed_redirect.hostname)

        parsed_qs = urllib.parse.parse_qs(parsed_loc.query)

        saml_request = parsed_qs.get('SAMLRequest', [])
        try:
            self.saml_request = saml_request[0]
        except IndexError:
            raise AuthnRequestError("No SAMLRequest found")

        relay_state = parsed_qs.get('RelayState', [])
        try:
            self.relay_state = relay_state[0]
        except IndexError:
            self.relay_state = None

    def check_from_reply(self, reply):
        raise NotImplementedError("Subclasses must implement this method")


class SamlResponse(object):
    def __init__(self):
        self.saml_response = None
        self.relay_state = None
        self.assertion_url = None

    def from_form(self, html_form):
        raise NotImplementedError("Subclasses must implement this method")

    def from_reply(self, reply):
        if reply.status_code != 200:
            raise SamlFlowError(reply.status.code)
        return self.from_form(reply.text)


# Subclasses of the request and response for Mellon and Keycloak
class MellonAuthnRequest(AuthnRequest):
    def __init__(self, resource, sp_url, idp_url):
        super(MellonAuthnRequest, self).__init__(resource, idp_url)
        self.sp_parsed_url = urllib.parse.urlparse(sp_url)

    def _check_mellon_redirect_from_reply(self, mellon_reply):
        # The first redirect will point at the SP again with relative path
        # /mellon/login? the parameters will include ?ReturnTo=DP and ?IdP=
        location = get_location_from_redirect(mellon_reply)
        if location is None:
            raise AuthnRequestError("No Location found in mellon redirect")

        parsed_loc = urllib.parse.urlparse(location)
        if parsed_loc.hostname != self.sp_parsed_url.hostname:
            raise AuthnRequestError("Mellon did redirect to the SP",
                                    self.sp_parsed_url.hostname,
                                    parsed_loc.hostname)
        if parsed_loc.path != '/mellon/login':
            raise AuthnRequestError("Mellon did not redirect to /mellon/login",
                                    "mellon/login", parsed_loc.path)

        parsed_qs = urllib.parse.parse_qs(parsed_loc.query)
        return_to = parsed_qs.get('ReturnTo', [])
        if return_to[0] != self.resource:
            raise AuthnRequestError("ReturnTo does not redirect to "
                                    "the resource",
                                    self.resource, return_to)
        idp = parsed_qs.get('IdP', [])
        parsed_idp = urllib.parse.urlparse(idp[0])
        if parsed_idp.hostname != self.idp_name:
            raise AuthnRequestError("Unexpected IdP value",
                                    self.idp_name,
                                    parsed_idp.hostname)

    def _check_idp_redirect_from_reply(self, idp_redirect):
        # Run the generic tests first
        super(MellonAuthnRequest,
              self)._check_idp_redirect_from_reply(idp_redirect)

        # mellon specific checks
        # at this point, mellon should set the cookie to cookietest
        if idp_redirect.cookies.get('mellon-cookie') != 'cookietest':
            raise AuthnRequestError("Unexpected mellon-cookie value",
                                    "cookietest",
                                    idp_redirect.cookies.get('mellon-cookie'))

    def check_from_reply(self, reply):
        # Mellon would return two replies, the first tells that in order to
        # access the protected resource, the client should visit a mellon
        # endpoint, the second redirects from the mellon endpoint to the IDP
        if len(reply.history) != 2:
            raise AuthnRequestError(f"Expected 2 redirects, "
                                     "got {len(reply.history)}")
        mellon_redirect, idp_redirect = reply.history
        self._check_mellon_redirect_from_reply(mellon_redirect)
        self._check_idp_redirect_from_reply(idp_redirect)


class KeycloakSamlResponse(SamlResponse):
    def __init__(self):
        super(KeycloakSamlResponse, self).__init__()

    def from_form(self, html_form):
        # FIXME - check the values
        soup = BeautifulSoup(html_form, 'html.parser')

        rstate_input = soup.find('input', attrs={'name': 'RelayState'})
        self.relay_state = rstate_input.get('value')
        # RelayState should point at the protected resource
        logging.debug(f"RelayState: {self.relay_state}")

        saml_response_input = soup.find('input',
                                        attrs={'name': 'SAMLResponse'})
        self.saml_response = saml_response_input.get('value')

        assertion_form = soup.find('form')
        self.assertion_url = assertion_form.get('action')
        # AssertionUrl should point at the /mellon/postResponse endpoint
        logging.debug(f"Assertion url: {self.assertion_url}")


class SamlIdp(object):
    def __init__(self, url, idp_type,
                 login_username_field='username',
                 login_password_field='password'):
        self.url = url

        parsed_url = urllib.parse.urlparse(url)
        self.name = parsed_url.hostname

        self.idp_type = idp_type
        self.login_page = {'username': login_username_field,
                           'password': login_password_field,
                           'action': None}

    def _get_single_html_attr(self, elem, attr_name):
        if len(elem) != 1:
            raise IndexError('Expected one element %s got %d', elem, len(elem))
        return elem[0].get(attr_name)

    def parse_login_form(self,
                         login_page,
                         form_el_name='form',
                         form_el_attrs=None,
                         form_action_attr_name='action'):
        soup = BeautifulSoup(login_page, 'html.parser')
        login_form_elem = soup.find_all(form_el_name, attrs=form_el_attrs)

        return self._get_single_html_attr(login_form_elem,
                                          form_action_attr_name)


class KeycloakIdp(SamlIdp):
    def __init__(self, url):
        super(KeycloakIdp, self).__init__(url, 'keycloak')

    def do_login(self, session, login_page, username, password):
        login_url = super(KeycloakIdp, self).parse_login_form(
                                        login_page,
                                        form_el_attrs={'id': 'kc-form-login'})

        logging.debug("Logging in to IDP as %s:%s", username, password)
        form_data = {'username': username, 'password': password}

        login_reply = session.post(url=login_url, data=form_data)
        logging.debug("IDP login reply: %s", login_reply)
        return login_reply

    def parse_saml_response(self, reply):
        saml_response = KeycloakSamlResponse()
        saml_response.from_reply(reply)
        return saml_response


class SpFactory(object):
    def __init__(self, resource, sp_type, sp_url, idp_name):
        if sp_type == 'mellon':
            self.assertion_path = "/mellon/postResponse"
            self.authn_req_cls = MellonAuthnRequest
            self.auth_req_instance_args = (resource, sp_url, idp_name)
        else:
            raise ValueError(f"Unsupported SP type {sp_type}")

    def authn_request(self, resource, idp):
        return self.authn_req_cls(*self.auth_req_instance_args)


class IdpFactory(object):
    def __init__(self, idp_type, idp_url):
        self.idp_url = idp_url

        if idp_type == 'keycloak':
            self.saml_response_cls = KeycloakSamlResponse
            self.idp = KeycloakIdp(idp_url)
        else:
            raise ValueError(f"Unsupported IdP type {idp_type}")

    def saml_response_parser(self, reply):
        saml_response = self.saml_response_cls()
        saml_response.from_reply(reply)
        return saml_response

    def idp_login(self, session, login_page, username, password):
        return self.idp.do_login(session, login_page, username, password)


class SamlLoginTest(object):
    def __init__(self, idp_factory, sp_factory, verify=True):
        self.idp_factory = idp_factory
        self.sp_factory = sp_factory
        self._session = None
        self.verify = verify

    @property
    def session(self):
        if self._session is None:
            self._session = requests.Session()
            self._session.verify = self.verify
        return self._session

    @session.setter
    def session(self, session):
        self._session = session

    def clear_session(self):
        self._session = None

    def _saml_response_post(self, session, response):
        form_data = {'SAMLResponse': response.saml_response,
                     'RelayState': response.relay_state}

        sp_consumer_reply = session.post(url=response.assertion_url,
                                         data=form_data)
        logging.debug(f"SP assertion consumer: {sp_consumer_reply}")
        return sp_consumer_reply

    def redirect_post_flow(self, url, username, password, page_check_fn=None):
        if username is None or password is None:
            raise NoCredentialsError

        logging.info("Running the WebSSO redirect-POST flow")

        # Eventually we should get a 200..
        document_get = self.session.get(url)
        if document_get.status_code != 200:
            raise SamlFlowError(document_get.status_code)
        logging.debug(document_get.url)

        # ..but behind the scenes we are redirected to the IDP, check
        # the SP-specific redirect
        authn_request = self.sp_factory.authn_request(url,
                                                      self.idp_factory.idp)
        authn_request.check_from_reply(document_get)
        logging.info("The AuthnRequest from SP to IDP is OK")

        # Try to login to the IdP
        login_reply = self.idp_factory.idp_login(self.session,
                                                 document_get.text,
                                                 username, password)
        if login_reply.status_code != 200:
            raise SamlFlowError(login_reply.status_code)

        logging.info(f"Logged in to the IDP as {username}")

        # check the response from the IDP
        # If the reply contained a ReturnTo, the response must match it
        saml_response = self.idp_factory.saml_response_parser(login_reply)
        if saml_response.relay_state != authn_request.relay_state:
            raise ValueError("The request and reply RelayState do not match")
        # the reply must also point to the SP postResponse endpoint
        assertion_path = urllib.parse.urlparse(
                                        saml_response.assertion_url).path
        if assertion_path != self.sp_factory.assertion_path:
            raise ValueError("The request and reply AssertionUrl do not match")

        logging.info(f"Verified the response from IDP")

        # The login returns 200 and a JS form in body which would normally
        # redirect us to the IDP. Since there is no JS in this python-requests
        # driven script, let's POST the reply ourselves to the SP
        sp_consumer_reply = self._saml_response_post(self.session,
                                                     saml_response)

        # Make sure we finally got to the URL we wanted initially
        if sp_consumer_reply.status_code != 200:
            raise SamlFlowError(sp_consumer_reply.status_code)
        logging.info(f"Reached the SP again")

        if not same_normalized_url(url, sp_consumer_reply.url):
            raise ValueError("Expected to reach a different location")
        logging.info(f"Retrieved {url} from the SP")

        # And make sure we got the contents we wanted initially
        if page_check_fn is not None and \
                page_check_fn(sp_consumer_reply.text) == False:
            raise ValueError("Expected to reach a different content")


def is_my_page(html_page):
    soup = BeautifulSoup(html_page, 'html.parser')
    if soup.title.string != "Secure":
        return False
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument('--idp-url', required=True)
    parser.add_argument('--idp-type', default='keycloak', choices=['keycloak'])
    parser.add_argument('--sp-url', required=True)
    parser.add_argument('--sp-type', default='mellon', choices=['mellon'])
    parser.add_argument('--username', action='store', type=str)
    parser.add_argument('--password', action='store', type=str)
    parser.add_argument('-d', '--debug', action='count', default=0)
    parser.add_argument('--no-verify', action='store_true')

    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels)-1, args.debug)]
    logging.basicConfig(level=level)

    logging.debug("Instatiated proxy to %s IdP at %s",
                  args.idp_type, args.idp_url)

    login_test = SamlLoginTest(IdpFactory(args.idp_type, args.idp_url),
                               SpFactory(args.url, args.sp_type,
                                         args.sp_url, args.idp_url),
                               not args.no_verify)

    # Gets the page using the WebSSO flow
    logging.info(f"About to run the WebSSO flow for {args.url} with "
                  "an empty session")
    login_test.redirect_post_flow(args.url,
                                  args.username, args.password,
                                  is_my_page)

    # Let's try fetching the page again, this should just succeed with
    # one redirect to mellon
    logging.info(f"Re-using cached session")
    sp_resource = login_test.session.get(args.url)
    assert len(sp_resource.history) == 1
    if not same_normalized_url(args.url, sp_resource.url):
        raise ValueError("Expected to reach a different location")
    logging.info(f"OK, retrieved {args.url} without contacting IdP")

    # ..but not if we remove the session
    logging.info(f"Clearing the session")
    login_test.clear_session()
    sp_resource = login_test.session.get(args.url)
    assert len(sp_resource.history) == 2
    logging.info(f"OK, got redirected to IdP again")
