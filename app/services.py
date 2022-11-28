import os
import logging
from typing import List, Union, Dict, Any

from requests import Session
from cachetools import cachedmethod, TTLCache
from datetime import datetime, timezone

import requests.packages.urllib3

requests.packages.urllib3.disable_warnings()

log = logging.getLogger('RVisionSOARIntegration')


def create_fields_list(fields_conf: Dict[str, List[Dict[str, str]]]):
    ret: Dict[str, str] = dict()
    for ioc_type, fields in fields_conf.items():
        for i in fields:
            ret[i['source']] = i['target']
    return ret


class RVisionSOARIntegration:
    def __init__(self, config: dict):
        self.cache = TTLCache(maxsize=1024, ttl=43200)
        self.SOAR_URL = config['soar'].get('url', 'https://127.0.0.1')
        self.SOAR_TOKEN = config['soar'].get('token', 'unknown')
        self.SOAR_TIMEOUT = config['soar'].get('timeout', 10)
        self.FIELDS = create_fields_list(config['soar'].get('fields', dict()))
        self.SOAR_FIELDS = str(list(self.FIELDS)).replace('\'', '"')
        self.SOAR_URL_API_INCIDENTS = self.SOAR_URL + '/api/v2/incidents'

        self.RST_URL = config['rst'].get('url', 'https://api.rstcloud.net')
        self.RST_TOKEN = config['rst'].get('token', 'unknown')
        self.RST_TIMEOUT = config['rst'].get('timeout', 10)
        self.RST_URL_API_IOC = self.RST_URL + '/v1/ioc'

        self.soar_session: Union[Session, None] = None
        self.rst_session: Union[Session, None] = None

    def create_sessions(self):
        if self.soar_session is None:
            self.soar_session = Session()
        if self.rst_session is None:
            self.rst_session = Session()

    def close_sessions(self):
        if self.soar_session is not None:
            self.soar_session.close()
            self.soar_session = None
        if self.rst_session is not None:
            self.rst_session.close()
            self.rst_session = None

    @cachedmethod(lambda self: self.cache)
    def enrich(self, ioc):
        ret: List[Dict[str, Any]] = list()
        response = self.exec_request(self.rst_session,
                                     self.RST_URL_API_IOC,
                                     timeout=self.RST_TIMEOUT,
                                     headers={'x-api-key': self.RST_TOKEN},
                                     params={'value': ioc})

        js = response.json()
        if js.get('error') is not None:
            if js['error'] == 'Not Found':
                return [{'rst_field': 'Unknown', 'rst_value': 'Not Found'}]
            log.error('Server return error: ' + str(js))
            raise Exception('Error: ' + str(js))
        ret.append({'rst_field': 'first_seen', 'rst_value': datetime.fromtimestamp(int(js['fseen']), tz=timezone.utc).strftime('%Y-%m-%d')})
        ret.append({'rst_field': 'last_seen', 'rst_value': datetime.fromtimestamp(int(js['lseen']), tz=timezone.utc).strftime('%Y-%m-%d')})
        ret.append({'rst_field': 'tags', 'rst_value': '\n'.join(js.get('tags', {}).get('str', []))})
        ret.append({'rst_field': 'links', 'rst_value': '\n'.join(js.get('src', {}).get('report', '').split(','))})
        ret.append({'rst_field': 'threats', 'rst_value': '\n'.join(js.get('threat', []))})
        ret.append({'rst_field': 'score', 'rst_value': int(js.get('score', {}).get('total', 0))})
        fp_alarm = js.get('fp', {}).get('descr', '')
        if fp_alarm == '':
            ret.append({'rst_field': 'fp_alarm', 'rst_value': 'Not FP'})
        else:
            ret.append({'rst_field': 'fp_alarm', 'rst_value': js.get('fp', {}).get('descr', '')})

        return ret

    def send_enriched_iocs(self, identifier: str):
        self.create_sessions()
        response = self.exec_request(self.soar_session,
                                     self.SOAR_URL_API_INCIDENTS,
                                     timeout=self.SOAR_TIMEOUT,
                                     headers={'X-Token': self.SOAR_TOKEN},
                                     params={'fields': self.SOAR_FIELDS,
                                             'filter': '[{"property": "identifier", "value": "' + identifier + '"}]'})
        js = response.json()
        if len(js) == 0:
            self.close_sessions()
            log.error('No incident body for id: {}'.format(identifier))
            return

        result = js.get('data', {}).get('result', [])
        if len(result) == 0:
            self.close_sessions()
            log.info('No iocs for id: {}'.format(identifier))
            return

        enriched_iocs: Dict = dict()
        for i in result:
            log.info('Get {} iocs for id: {}'.format(len(i), identifier))
            for source_field, ioc in i.items():
                if ioc is None: continue
                target_field: str = self.FIELDS.get(source_field)
                enriched_iocs[target_field] = self.enrich(ioc)

        log.info('Try to update incident with id: {}'.format(len(enriched_iocs), identifier))
        body = dict()
        body['identifier'] = identifier
        body.update(enriched_iocs)
        self.exec_request(self.soar_session,
                          self.SOAR_URL_API_INCIDENTS,
                          method='POST',
                          timeout=self.SOAR_TIMEOUT,
                          headers={'X-Token': self.SOAR_TOKEN},
                          json=body)

        self.close_sessions()
        log.info('Jobs done for id: {}'.format(identifier))
        return enriched_iocs

    def exec_request(self, session: requests.Session, url: str, method='GET', timeout=30, timeout_up=1,
                     **kwargs) -> requests.Response:
        """
        Выполнение HTTP запросов
        Если в окружении DEBUG_LOG_BODY, выводит в DEBUG лог сырой ответ от сервера

        :param session:
        :param url:
        :param method: метод GET|POST
        :param timeout: timeout соединения
        :param timeout_up: увеличение timeout от базового на коэффициент (нужно при генерации отчетов)
        :param kwargs: параметры запроса, передаваемые в requests
        :return: requests.Response
        """

        log_body = "DEBUG_LOG_BODY" in os.environ
        if log_body:  # включаем verbose для requests
            import http.client as http_client
            http_client.HTTPConnection.debuglevel = 1

        response = None
        log.debug('status=prepare, action=request, '
                  'msg="Try to exec request", '
                  'url="{}", method="{}", body="{}", headers="{}", '
                  'parameters="{}"'.format(url, method,
                                           str(kwargs.get('data')) + str(kwargs.get('json')) if log_body else 'masked',
                                           kwargs.get('headers'),
                                           kwargs.get('params'))
                  )

        try:
            if method == 'POST':
                response = session.post(url,
                                        verify=False,
                                        timeout=(timeout * timeout_up, timeout * timeout_up * 2),
                                        **kwargs)
            elif method == 'DELETE':
                response = session.delete(url,
                                          verify=False,
                                          timeout=(timeout * timeout_up),
                                          **kwargs)
            elif method == 'PUT':
                response = session.put(url,
                                       verify=False,
                                       timeout=(timeout * timeout_up),
                                       **kwargs)
            else:
                response = session.get(url,
                                       verify=False,
                                       timeout=(timeout * timeout_up, timeout * timeout_up * 2),
                                       **kwargs)
            response.raise_for_status()
            if response.status_code >= 400:
                raise Exception()
        except Exception as err:
            log.error('url="{}", status=failed, action=request, msg="{}", '
                      'error="{}", code={}'.format(url,
                                                   err,
                                                   response.text if response is not None else '',
                                                   response.status_code if response is not None else '0'))
            raise err

        if log_body:
            log.debug('status=success, action=request, msg="{}"'.format(response.text))

        return response
