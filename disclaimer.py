#!/usr/bin/env python
# encoding: utf-8

import os
import sys
import logging
import json
import re
import base64
import pickle
import argparse

import requests
from bs4 import BeautifulSoup
#from logger_handler import init_logger
#logger = logging.getLogger(__name__)
#init_logger(logger=logger, level=logging.DEBUG)
api_data_file = os.path.join(os.getcwd(), 'apidata.pkl')

groups_list = [
    'Projects',
    'Scans',
    'Quick_scan',
    'Components',
    'Licenses',
    'Users',
    'Files_and_folders',
    'JIRA',
    'Component_approval',
]


def is_code_file(file_name):
    code_file_types = ['.c', '.h', '.cpp', '.hpp', '.py', '.pl', '.java', '.cs']
    _, ext = os.path.splitext(file_name)
    return ext in code_file_types


def print_json(data):
    print(
        json.dumps(
            data, sort_keys=True, indent=4, separators=(', ', ': '), ensure_ascii=False,
        )
    )


def base64_encode(string):
    return base64.b64encode(bytes(string, 'utf-8')).decode()


class FossIdApiException(Exception):
    operation = ""
    status = ""
    error = ""


class FossID:
    def __init__(self, **kwargs):
        self._username = ''
        self._password = ''
        if not all((self._username is not None, self._password is not None)):
            raise RuntimeError('Invalid username or password')
        # self._user_id = ''
        self._user_api_key = ''
        self._api_url = 'https://rb-fossid.de.bosch.com/AE/api.php'
        self._index_url = 'https://rb-fossid.de.bosch.com/AE/index.php'
        self._ajax_handler_url = 'https://rb-fossid.de.bosch.com/AE/ajax-handler.php'
        self._api_groups_actions = {}
        self.false_positive_match_name = 'False Positive Match'
        self.false_positive_match_ver = '1.0'
        self.copyright_comment = 'No OSS, just copyright comment match'
        self._http_proxy_bosch_na = "http://rb-proxy-na.bosch.com:8080"
        self._proxies = {
            'http': self._http_proxy_bosch_na,
            'https': self._http_proxy_bosch_na
        } if kwargs.get('proxy', None) else None

        self._session = requests.session()
        self._cookies = self._session.cookies
        self.login_success = False

    def init(self):
        try:
            #logger.info("Initializing, please wait...")
            print("Initializing, please wait...")
            # self._user_id = self.get_user().json()['data']['id']
            userid = self.get_user().json()['data']['id']
            self._user_api_key = self.retrieve_api_key(userid)
            if not os.path.exists(api_data_file):
                self._api_groups_actions = self.api_groups_actions()
                if self._api_groups_actions:
                    with open(api_data_file, 'wb') as f:
                        pickle.dump(self._api_groups_actions, f)
            else:
                with open(api_data_file, 'rb') as f:
                    self._api_groups_actions = pickle.load(f)
        except Exception as e:
            #logger.error(f'Initialize failed, {e}')
            print(f'Initialize failed, {e}')

    def _request(self, url, method='post', **kwargs):
        response = self._session.request(method=method, url=url, **kwargs)
        if not response.ok:
            response.raise_for_status()
        else:
            return response

    def login(self, username, password):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
        payload = {
            "group": "Internal",
            "action": "login",
            "data": {"username": username, "password": password},
        }
        payload = json.dumps(payload)
        response = self._request(self._index_url, headers=headers, data=payload)
        if response.json()['status'] == 1:
            # self._username = username
            # self._password = password
            self.login_success = True
            #logger.info("Login successful")
            print("Login successful")
            self._username, self._password = username, password
            return response
        else:
            self.login_success = False
            raise requests.RequestException(
                response.json()
                .get('error', {})
                .get('message', 'No Error Message Found')
            )

    def get_user(self):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
        payload = {
            "group": "Internal",
            "action": "getUser",
            "data": {"username": self._username, "password": self._password},
        }
        payload = json.dumps(payload)
        response = self._request(self._index_url, headers=headers, data=payload)
        if response.json()['status'] == 1:
            return response
        else:
            raise requests.RequestException(response.json()['error'])

    def _logout(self):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
        payload = {
            'action': 'logout',
        }
        response = self._request(self._index_url, headers=headers, data=payload)
        if response.ok:
            #logger.info('Logged out')
            print("Logged out")
            self.login_success = False
        else:
            #logger.error(json.loads(response.text)['error'])
            print(json.loads(response.text)['error'])
            sys.exit()

    def api_groups_actions(self):
        payload = {
            "action": "pusher",
            "data": {"username": self._username, "password": self._password},
        }
        response = self._request(self._index_url, method='get', params=payload)
        soup_group = BeautifulSoup(response.text, features="html.parser")
        # groups = [option.text for option in soup.find(id="group_select").children]
        groups = list(soup_group.find(id="group_select").children)
        groups_actions = {'groups': dict().fromkeys([group.text for group in groups])}
        for group in groups:
            data = {
                "action": "pusher",
                "pgroup": str(group.text).lower(),
                "data": {"username": self._username, "password": self._password},
            }
            response = self._request(self._index_url, method='get', params=data)
            soup_action = BeautifulSoup(response.text, features="html.parser")
            actions = list(soup_action.find(id="action_select").children)
            groups_actions['groups'][group.text] = {}
            groups_actions['groups'][group.text].update(
                {'actions': dict().fromkeys([action.text for action in actions])}
            )
            for action in actions:
                data = {
                    "action": "pusher",
                    "pgroup": str(group.text).lower(),
                    "paction": str(action.text).lower(),
                    "data": {"username": self._username, "password": self._password},
                }
                response = self._request(self._index_url, method='get', params=data)
                soup_pre = BeautifulSoup(response.text, features="html.parser")
                pre = soup_pre.find(name='pre').text
                groups_actions['groups'][group.text]['actions'][action.text] = {}
                groups_actions['groups'][group.text]['actions'][action.text].update(
                    {'form_data': json.loads(pre)}
                )
        return groups_actions

    def webapi_request(self, group, action, **kwargs):
        payload = (
            self._api_groups_actions.get('groups', {})
            .get(group, {})
            .get('actions', {})
            .get(action, {})
            .get('form_data', None)
        )
        assert payload
        payload['data'].update(kwargs)
        payload['data'].update({'username': self._username, 'key': self._user_api_key})
        data = json.dumps(payload)
        response = requests.post(url=self._api_url, data=data)
        if not response.ok:
            response.raise_for_status()
        content_type = (
            response.headers.get('Content-Type', '').split(';')[0].strip().lower()
        )

        try:
            if content_type != 'application/json' or response.json().get('status', "0") == '1':
                return response
            api_error = FossIdApiException()
            api_error.__dict__.update(response.json())
            raise api_error
        except FossIdApiException as ex:
            #logger.error(f'{ex.operation}: {ex.error}')
            print(f'{ex.operation}: {ex.error}')
            return

    def mark_as_false_positive_match(
        self, arg0, scan, filename,
    ):
        #logger.info(arg0)
        print(arg0)
        preserve_existing_identifications = '0'
        clear_previous_comments = False
        _ = self.webapi_request(
            group='files_and_folders',
            action='set_identification_component',
            scan_code=scan['code'],
            path=base64_encode(filename),
            component_name=self.false_positive_match_name,
            component_version=self.false_positive_match_ver,
            is_directory=str(int(os.path.isdir(filename))),
            preserve_existing_identifications=preserve_existing_identifications,
        )
        if clear_previous_comments:
            for parameter, comment in self.get_identification_comments(
                sid=scan['id'], path=filename
            ).items():
                if comment == self.copyright_comment:
                    self.del_identification_comments(sid=scan['id'], parameter=parameter)
        _ = self.webapi_request(
            group='files_and_folders',
            action='add_file_comment',
            scan_code=scan['code'],
            path=base64_encode(filename),
            comment=self.copyright_comment,
            is_important='0',
            include_in_report='1',
        )
        _ = self.webapi_request(
            group='files_and_folders',
            action='mark_as_identified',
            scan_code=scan['code'],
            path=base64_encode(filename),
            is_directory=str(int(os.path.isdir(filename))),
        )
        #logger.info('Marked identification "False Positive Match"')
        print('Marked identification "False Positive Match"')

    def generate_report(
        self,
        scancode,
        report_type="dynamic",
        selection_type="include_all_licenses",
        selection_view="",
        disclaimer="",
    ):
        cur_dir = os.getcwd()
        report_folder = os.path.join(cur_dir, "reports")
        os.makedirs(report_folder, exist_ok=True)
        response = self.webapi_request(
            group='scans',
            action='generate_report',
            scan_code=scancode,
            report_type=report_type,
            selection_type=selection_type,
            selection_view=selection_view,
            disclaimer=disclaimer,
        )
        report_file_name = response.headers['content-disposition']
        m = re.search(r'fossid-.+\.html', report_file_name)
        if m:
            # print('m', m)
            report_file_name = m.group().replace("/", "_")
            scan_report_file = os.path.join(report_folder, report_file_name)
            report_text = response.text
            with open(scan_report_file, 'wb') as f:
                f.write(report_text.encode('utf-8'))
            #logger.info(f"Scan report saved: {scan_report_file}.")
            print(f"Scan report saved: {scan_report_file}.")
        else:
            #logger.warning("failed to find generated report file")
            print("failed to find generated report file")

    def retrieve_api_key(self, userid):
        # params = {'action': 'get_csrf_token'}
        # response = self._request(self._index_url, method='get', params=params)
        params = {
            # 'form': 'main_interface',
            'action': 'print_user_form',
            'parameter': str(userid),
        }
        response = self._request(self._index_url, method='get', params=params)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, features="html.parser")
            return soup.find(id="user_api_key").string

        else:
            #logger.error(json.loads(response.text)['error'])
            print(json.loads(response.text)['error'])
            sys.exit(1)

    def set_usr_api_key(self, key):
        self._user_api_key = key

    def file_download_local(self, scan_id, path):
        payload = {
            'form': 'scan',
            'action': 'file_download_local',
            'sid': scan_id,
            'path': path,  # path of the local file, encoded in base64
        }
        # payload.update(kwargs)
        response = self._request(url=self._index_url, method='get', params=payload)
        return response.text

    def file_download_fossid(self, scan_id, mirror_base64):
        payload = {
            'form': 'scan',
            'action': 'file_download_fossid',
            'sid': scan_id,
            'url': mirror_base64,  # ID of the mirror file, encoded in base64
        }
        return self._request(url=self._index_url, params=payload).text

    @staticmethod
    def remove_block_comment(text):
        # text = text.decode('utf8')
        copyright_blk_pattern = r'/\*.*?(Copyright)?.*?\*/'
        m = re.compile(copyright_blk_pattern, re.S)
        return re.sub(m, '', text)

    @staticmethod
    def remove_line_comment(text):
        p = r"^\s*[//].*$"
        text_list = text.splitlines(keepends=True)
        out_list = [ln for ln in text_list if not re.match(p, ln)]
        return "".join(out_list)

    def clean_comment(self, text):
        cprt_cleaned = self.remove_block_comment(text)
        return self.remove_line_comment(cprt_cleaned)

    def get_identification_comments(self, sid, path):
        url = f"{self._index_url}?sid={sid}&action=print_identification_comments&path={base64_encode(path)}"
        response = self._request(url)
        soup = BeautifulSoup(response.text, features="html.parser")
        comment_ids = [
            re.search(r'\d+', content.attrs['onclick'])[0]
            for content in soup.find_all(title='Delete comment')
        ]
        comment_contents = (pre.text for pre in soup.find_all(name='pre'))
        return dict(zip(comment_ids, comment_contents))

    def del_identification_comments(self, sid, parameter):
        url = f"{self._index_url}?sid={sid}&action=delete_comment&parameter={parameter}"
        return self._request(url)

    def process_a_file(self, scan, filename):
        if not is_code_file(filename):
            #logger.info('Not source code file, skipped.')
            print('Not source code file, skipped.')
            return
        matches = self.webapi_request(
            group='files_and_folders',
            action='get_fossid_results',
            scan_code=scan['code'],
            path=base64_encode(filename),
        ).json()['data']
        if 'full' in [match.get('match_type', '') for match in matches.values()]:
            #logger.info("Full file match found")
            print("Full file match found")
            return
        lines = []
        unable_to_read_remote_file = True
        for matchid, match in matches.items():
            iretry, retry_max = 0, 5
            while iretry < retry_max:
                matched_lines = self.webapi_request(
                    group='files_and_folders',
                    action='get_matched_lines',
                    scan_code=scan['code'],
                    path=base64_encode(filename),
                    mirror_base64=base64_encode(match['mirror']),
                    client_result_id=matchid,
                )
                if matched_lines is not None:
                    lines += list(
                        matched_lines.json()['data']['local_file'].values()
                    )
                    unable_to_read_remote_file = True
                    break
                else:
                    iretry += 1
            else:
                unable_to_read_remote_file = False
                break

        if not unable_to_read_remote_file:
            #logger.warning("Cannot read fossid remote mirror file.")
            print("Cannot read fossid remote mirror file.")
            return
        mergedlines = sorted(list({int(line) - 1 for line in lines}))
        if not mergedlines:
            self.mark_as_false_positive_match("No matched line found.)", scan, filename)
            return
        full_text = self.file_download_local(
            scan_id=scan['id'], path=base64_encode(filename),
        )
        full_text_list = full_text.splitlines(keepends=True)
        if len(mergedlines) == len(full_text_list):
            #logger.info("Local file full matched with mirrors aggregation.)")
            print("Local file full matched with mirrors aggregation.)")
            return
        matched_text_list = [full_text_list[i] for i in mergedlines]
        matched_text = "".join(matched_text_list)
        comment_cleaned = self.clean_comment(full_text)
        for cleaned_line in comment_cleaned.splitlines():
            if cleaned_line in matched_text:
                if not re.search(r'\w+', cleaned_line):
                    continue
                #logger.info("Code matched found.")
                print("Code matched found.")
                break
        else:
            self.mark_as_false_positive_match("No Code matched found.", scan, filename)
            return

    def process_a_scan(self, scancode):
        #logger.info("Scan start")
        print("Scan start")
        scan = self.webapi_request(
            group='scans', action='get_information', scan_code=scancode
        ).json()['data']
        pending_files = self.webapi_request(
            group='scans', action='get_pending_files', scan_code=scan['code']
        ).json()['data']
        #logger.info(f"{len(pending_files)} pending files found.")
        print(f"{len(pending_files)} pending files found.")
        if not pending_files or len(pending_files) == 0:
            return
        for ifile, (_, filename) in enumerate(pending_files.items(), start=1):
            #logger.info(f"{filename}({ifile}/{len(pending_files)})")
            print(f"{filename}({ifile}/{len(pending_files)})")
            self.process_a_file(scan, filename)

        pending_files = self.webapi_request(
            group='scans', action='get_pending_files', scan_code=scan['code']
        ).json()['data']
        pending_files_count = len(pending_files) if pending_files else 0
        marked_files = self.webapi_request(
            group='scans', action='get_marked_as_identified_files', scan_code=scan['code']
        ).json()['data']
        marked_files_count = len(marked_files) if marked_files else 0
        #logger.info("Scan finished")
        print("Scan finished")
        #logger.info(f"{marked_files_count} files marked as identified, {pending_files_count} files pending identification")
        print(f"{marked_files_count} files marked as identified, {pending_files_count} files pending identification")
        return


def main(username, password, scancode):
    try:
        fid = FossID()
        fid.login(username, password)
        fid.init()
        fid.process_a_scan(scancode=scancode)
        fid.generate_report(scancode=scancode)

    except requests.RequestException as e:
        #logger.error(e)
        print(e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='username, password and scan_code arguments are required to start')
    parser.add_argument('-u', '--username', dest='username', metavar='username', required=True)
    parser.add_argument('-p', '--password', dest='password', metavar='password', required=True)
    parser.add_argument('-s', '--scancode', dest='scancode', metavar='scancode', required=True)
    args = parser.parse_args()
    main(args.username, args.password, args.scancode)

