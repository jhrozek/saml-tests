#!/usr/bin/python3

import argparse
import logging

import requests
from bs4 import BeautifulSoup

username = 'tuser'
password = 'Secret123'
idp_url = 'https://keycloak.federation.test'

def kc_parse_login_url(html_page):
    soup = BeautifulSoup(html_page, 'html.parser')

    login_forms = soup.find_all('form', id='kc-form-login')
    assert len(login_forms) == 1
    return login_forms[0]['action']

def kc_do_login(session, login_url, username, password):
    form_data = data={ 'username': username, 'password': password }
    login_reply = session.post(url=login_url, data = form_data)
    logging.debug("IDP login reply: %s\n", login_reply)
    return login_reply

def kc_parse_login_reply(login_reply):
    assert login_reply.status_code == 200

    soup = BeautifulSoup(login_reply.text, 'html.parser')

    rstate_input = soup.find_all('input', attrs={'name':'RelayState'})
    assert len(rstate_input) == 1
    rstate = rstate_input[0]['value']

    saml_response_input = soup.find_all('input', attrs={'name':'SAMLResponse'})
    assert len(saml_response_input) == 1
    saml_response = saml_response_input[0]['value']

    sp_assertion_url = soup.find_all('form')[0]['action']

    # TODO: This should probably return a constructed request also
    # with the mellon-cookie cookie set or at least a dict
    return (sp_assertion_url, rstate, saml_response)

def post_to_assertion_consumer(session,
                               sp_assertion_url,
                               relay_state,
                               saml_response):
    form_data = data={ 'SAMLResponse': saml_response,
                       'RelayState': relay_state }

    sp_consumer_reply = session.post(url=sp_assertion_url, data = form_data)
    logging.debug("SP assertion consumer: %s\n", sp_consumer_reply)
    return sp_consumer_reply

def saml_login(url, idp_url, username, password):
    session = requests.Session()

    # make sure we are redirected to the IDP
    resp = session.get(url)
    assert resp is not None
    assert resp.status_code == 200

    # TODO: check the chain of redirects
    # The first redirect will point at the SP again with relative path /mellon/login?
    # the parameters will include ?ReturnTo=DP and ?IdP=

    # The second redirect will set a mellon cookie, the URL will point at the
    # ?IdP parameter from the first request

    # the IDP should be keycloak
    # TODO: load a login form parser class depending on what the IDP is
    logging.debug("IDP URL: %s\n", idp_url)
    assert resp.url.startswith(idp_url)

    # the IDP is keycloak so the login form should contain a login form
    login_url = kc_parse_login_url(resp.text)
    logging.debug("login URL: %s\n", login_url)

    # log in
    login_reply = kc_do_login(session, login_url, username, password)

    # The login returns 200 and a JS form in body which would normally redirect
    # us to the IDP. Since there is no JS in this
    # python-requests driven script, let's POST the reply ourselves to the SP
    sp_assertion_url, rstate, saml_response = kc_parse_login_reply(login_reply)
    sp_assertion_reply = post_to_assertion_consumer(session,
                                                    sp_assertion_url,
                                                    rstate, saml_response)
    logging.debug("Consumer reply: %s\n", sp_assertion_reply)

    # The assertion reply should redirect us to the originally requested page
    print(sp_assertion_reply.text)

class SamlResponse(object):
    def __init__(self):
        self.saml_response = None
        self.relay_state = None
        self.assertion_url = None

    def from_form(self, html_form):
        raise NotImplementedError("Subclasses can implement this method")

    def from_reply(self, reply):
        assert reply.status_code == 200
        return self.from_form(reply.text)


class KeycloakSamlResponse(SamlResponse):
    def __init__(self):
        # FIXME: Read something on inheritance..
        super(KeycloakSamlResponse, self).__init__()

    def from_form(self, html_form):
        soup = BeautifulSoup(html_form, 'html.parser')

        rstate_input = soup.find_all('input', attrs={'name':'RelayState'})
        assert len(rstate_input) == 1
        self.relay_state = rstate_input[0]['value']

        saml_response_input = soup.find_all('input', attrs={'name':'SAMLResponse'})
        assert len(saml_response_input) == 1
        self.saml_response = saml_response_input[0]['value']

        self.assertion_url = soup.find_all('form')[0]['action']


class SamlIdp(object):
    def __init__(self, url, idp_type,
                 login_username_field='username',
                 login_password_field='password'):
        self.url = url
        self.idp_type = idp_type
        self.login_page = {'username':login_username_field,
                           'password':login_password_field,
                           'action':None}

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
        # FIXME - should we pass around Requests and Replies as opaque objects?
        form_data = { 'username': username, 'password': password }
        login_url = super(KeycloakIdp, self).parse_login_form(
                                        login_page,
                                        form_el_attrs={'id':'kc-form-login'})

        logging.debug("Logging in to IDP as %s:%s\n", username, password)
        login_reply = session.post(url=login_url, data=form_data)
        logging.debug("IDP login reply: %s\n", login_reply)
        return login_reply

    def parse_saml_response(self, reply):
        saml_response = KeycloakSamlResponse()
        saml_response.from_reply(reply)
        return saml_response


class SamlLoginTest(object):
    def __init__(self, idp):
        self.idp = idp

    def _saml_response_post(self, session, response):
        form_data = data={ 'SAMLResponse': response.saml_response,
                           'RelayState': response.relay_state }

        sp_consumer_reply = session.post(url=response.assertion_url,
                                         data=form_data)
        logging.debug("SP assertion consumer: %s\n", sp_consumer_reply)
        return sp_consumer_reply

    def get_page_with_login(self, url, username, password, page_check_fn=None):
        # FIXME: throw an exception if no username or password are defined
        session = requests.Session()

        # make sure we are redirected to the IDP
        document_get = session.get(url)
        assert document_get is not None
        assert document_get.status_code == 200
        logging.debug(document_get.url)
        assert document_get.url.startswith(self.idp.url)
        # TODO: since this is a mellon test, we should check that the URL contains
        # a SAMLRequest and a RelayState

        # Try to login to the IdP
        login_reply = self.idp.do_login(session, document_get.text, username, password)
        assert login_reply.status_code == 200

        # The login returns 200 and a JS form in body which would normally redirect
        # us to the IDP. Since there is no JS in this
        # python-requests driven script, let's POST the reply ourselves to the SP
        saml_response = self.idp.parse_saml_response(login_reply)
        sp_consumer_reply = self._saml_response_post(session, saml_response)

        # Make sure we finally got to the URL we wanted initially
        # FIXME: should probably use urllib to parse the URLs
        if not url.endswith('/'):
            url += '/'
        if not sp_consumer_reply.url.endswith('/'):
            sp_consumer_reply.url += '/'
        logging.debug(url)
        logging.debug(sp_consumer_reply.url)
        assert sp_consumer_reply.status_code == 200
        assert sp_consumer_reply.url == url

        if page_check_fn != None:
            assert page_check_fn(sp_consumer_reply.text) == True

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
    parser.add_argument('--username', action='store', type=str)
    parser.add_argument('--password', action='store', type=str)

    args = parser.parse_args()
    # TODO: Add a -d/-dd/-ddd argument
    logging.basicConfig(level=logging.DEBUG)

    if args.idp_type == 'keycloak':
        idp = KeycloakIdp(args.idp_url)
    else:
        raise ValueError("Unsupported IdP type %s\n", args.idp_type)
    logging.debug("Instatiated proxy to %s IdP at %s\n", args.idp_type, args.idp_url)

    login_test = SamlLoginTest(idp)
    login_test.get_page_with_login(args.url,
                                   args.username, args.password,
                                   is_my_page)
