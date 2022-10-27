from unittest import TestCase

try:
    from unittest.mock import patch, ANY as MOCK_ANY
except ImportError:
    from mock import patch, ANY as MOCK_ANY

import sandboxapi

class TestSandboxAPI(TestCase):

    @patch('requests.post')
    @patch('requests.get')
    def test_proxies_is_passed_to_requests(self, m_get, m_post):
        m_get.return_value.status_code = 200
        m_post.return_value.status_code = 200

        proxies = {
            'http': 'http://10.10.1.10:3128',
            'https': 'http://10.10.1.10:1080',
        }

        api = sandboxapi.SandboxAPI(proxies=proxies)
        api.api_url = 'http://sandbox.mock'
        api._request('/test')

        m_get.assert_called_once_with('http://sandbox.mock/test', auth=None,
                                      headers=None, params=None, proxies=proxies,
                                      verify=True)

        api._request('/test', method='POST')

        m_post.assert_called_once_with('http://sandbox.mock/test', auth=None,
                                       headers=None, data=None, files=None,
                                       proxies=proxies, verify=True)
