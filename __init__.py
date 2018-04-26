# -*- coding: utf-8 -*-
import os
import re
import requests
from requests.structures import CaseInsensitiveDict

http = requests.session()

def mkdir_0777(dirname):
    if not os.path.isdir(dirname):
        os.mkdir(dirname)
        os.chmod(dirname, 0o777)
    return dirname


def mkfile_0777(filename):
    if not os.path.isfile(filename):
        try:
            open(filename, 'w').close()  # Create a file if not exist
            os.chmod(filename, 0o777)
        except IOError:
            pass
    return filename

  
def get_proxies_dict(proxy):
    match = re.findall(r'^([0-9]+(?:\.[0-9]+){3}):([0-9]+):?([^:]*):?([^:]*)', proxy)
    if match:
        host, port, username, password = match[0]
        if host and port:
            if username and password:
                url = "http://%s:%s@%s:%s" % (username, password, host, port)
            else:
                url = "http://%s:%s" % (host, port)
            return {'http': url, 'https': url}
    raise Exception("Not valid format proxy with %s" % proxy)


def extract_html_form(html_page, pattern=r''):
    if not pattern:
        pattern = r'<form.*?>.*?</form>'
    matches = re.search(re.compile(pattern, re.DOTALL), html_page)
    del html_page
    if matches:
        html_form = matches.group(0)
        form = {}
        # Extract form method
        del matches
        matches = re.search(r'method="(.*?)"', html_form)
        if matches:
            form['method'] = matches.group(1)
        else:
            form['method'] = ''
        # Extract form action
        del matches
        matches = re.search(r'action="(.*?)"', html_form)
        if matches:
            form['action'] = matches.group(1)
        else:
            form['action'] = ''
        del matches
        # Extract form fields
        form['fields'] = {}
        matches = re.findall(r'<input.*?/?>', html_form)
        if matches:
            for input_field in matches:
                input_matches = re.search(r'name="(.*?)"', input_field)
                if input_matches:
                    field_name = input_matches.group(1)
                    del input_matches
                    input_matches = re.search(r'value="(.*?)"', input_field)
                    if input_matches:
                        form['fields'][field_name] = input_matches.group(1)
                    else:
                        form['fields'][field_name] = ''
                    del input_matches
        del matches
        matches = re.findall(r'<textarea.*?>.*</textarea>', html_form)
        if matches:
            for text_field in matches:
                text_matches = re.search(r'name="(.*?)"', text_field)
                if text_matches:
                    field_name = text_matches.group(1)
                    del text_matches
                    text_matches = re.search(r'>(.*?)<', text_field)
                    if text_matches:
                        form['fields'][field_name] = text_matches.group(1)
                    else:
                        form['fields'][field_name] = ''
                    del text_matches
        del matches
        form['html'] = html_form
        return form
    return None


def raise_for_status(response):
    """
    raise_for_status
    :param requests.models.Response response:
    """
    error = None
    if isinstance(response.reason, bytes):
        try:
            reason = response.reason.decode('utf-8').upper()
        except UnicodeDecodeError:
            reason = response.reason.decode('iso-8859-1').upper()
    else:
        reason = response.reason
    if 400 <= response.status_code < 500:
        if not error:
            error = u'%s Client Error: %s' % (response.status_code, reason)
    elif 500 <= response.status_code < 600:
        if not error:
            # error = u'%s Server Error: %s for url: %s' % (response.status_code, reason, response.url)
            error = u'%s Server Error: %s' % (response.status_code, reason)
    if error:
        if 'json' in response.headers.get('Content-Type', ''):
            try:
                result = response.json()
                if result['error'] is not None:
                    error = u'{0} [{1}]'.format(error, result['error'])
            except (ValueError, KeyError, IndexError):
                pass
        error = u'{0} on url: {1}'.format(error, response.url)
        raise Exception(error)


def request(url, params=None, data=None, headers=None, ajax=False, method=None):
    if not method:
        method = 'GET'
    elif isinstance(method, bytes):
        try:
            method = method.decode('utf-8').upper()
        except UnicodeDecodeError:
            method = method.decode('iso-8859-1').upper()
    else:
        raise TypeError("Expected HTTP request method as a str or None type")
    assert (method in ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']), 'Unsupported HTTP Request method.'
    _headers = CaseInsensitiveDict([
        ('Accept', 'text/html,image/webp,image/apng,*/*;q=0.8'),
        ('Accept-Encoding', 'gzip, deflate'),
        ('Accept-Language', 'en-US,en;q=0.8'),
        ('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7'),
        ('Cache-Control', 'no-cache'),
        ('Connection', 'keep-alive'),
        ('Host', ''),
        ('Origin', ''),
        ('Referer', ''),
        ('User-Agent', '')])
    if data is not None:
        if method == 'GET':
            method = 'POST'
        # If data is empty but not None. We will post with no body. So no Content-Type header set
        if data:
            _headers.update([('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')])
    if ajax:
        _headers.update([('Accept', 'application/json')])
        csrftoken = http.cookies.get('csrftoken')
        if csrftoken:
            _headers.update([('X-CSRFToken', csrftoken)])
        _headers.update([('X-Requested-With', 'XMLHttpRequest')])
    if headers:
        _headers.update(headers)
    try:
        response = http.request(method, url, params=params, data=data, headers=_headers, timeout=60)
    except Exception as ex:
        raise Exception("Request Error, %s(%s) on %s" % (ex.__class__.__name__, ex.message, url))
    raise_for_status(response)
    return response
