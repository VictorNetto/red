"""
Take incoming HTTP requests having specifieds headers/cookies and replay them
without these headers/cookies. The script also compare the reponse to find
possible diferences indicating the lack of proper authentication.
"""

from collections.abc import Sequence
import logging
import os

from mitmproxy import ctx
from mitmproxy import http
from mitmproxy import addonmanager
from mitmproxy.net.http.http1 import assemble

class FlowStorage:
    def __init__(self):
        self.raw_request: dict[str, bytes] = {}
        self.raw_response: dict[str, bytes] = {}
        self.hash_response_body: dict[str, int] = {}
        self.status_code: dict[str, int] = {}

    def put_raw_request(self, flow_id: str, raw_request: bytes):
        self.raw_request[flow_id] = raw_request

    def put_raw_response(self, flow_id: str, raw_response: bytes):
        self.raw_response[flow_id] = raw_response
    
    def put_response_body(self, flow_id: str, response_body: bytes):
        self.hash_response_body[flow_id] = hash(response_body)
    
    def put_status_code(self, flow_id: str, status_code: int):
        self.status_code[flow_id] = status_code
    
    def pop(self, flow_id: str):
        data = self.raw_request[flow_id] + self.raw_response[flow_id]

        del self.raw_request[flow_id]
        del self.raw_response[flow_id]
        del self.hash_response_body[flow_id]
        del self.status_code[flow_id]

        return data
    
    def equal(self, flow_id1: str, flow_id2: str):
        hash_response_body1 = self.hash_response_body.get(flow_id1, '')
        hash_response_body2 = self.hash_response_body.get(flow_id2, '')
        status_code1 = self.status_code.get(flow_id1, '')
        status_code2 = self.status_code.get(flow_id2, '')

        if hash_response_body1 == '' or hash_response_body2 == '' or \
            status_code1 == '' or status_code2 == '':
            return None

        same_response_body = hash_response_body1 == hash_response_body2
        same_status_code = status_code1 == status_code2

        return same_response_body and same_status_code

# Track request/response pairs (original and replayed one), comparing them as soon as possible
# Request/reponse pairs are tracked using its flow.id in add_pair method
# Comparison between them are made in add_content method using the auxiliar FlowStorage instance
#
class Comparator:
    undefined = -1
    equal = 0
    different = 1

    def __init__(self, flow_storage: FlowStorage):
        self.pairs: dict[str, str] = {}
        self.flow_storage = flow_storage
        # self.content = {}
    
    def add_pair(self, flow_id1: str, flow_id2: str):
        self.pairs[flow_id1] = flow_id2
        self.pairs[flow_id2] = flow_id1
    
    def add_content(self, flow_id: str, response_body: bytes, status_code: int):
        self.flow_storage.put_response_body(flow_id, response_body)
        self.flow_storage.put_status_code(flow_id, status_code)

        other_flow_id = self.pairs.get(flow_id, '')

        result = (Comparator.undefined, '', '')

        flows_are_equal = self.flow_storage.equal(flow_id, other_flow_id)
        if flows_are_equal is not None:
            if flows_are_equal:
                logging.warning(f"Replayed request with equal responses: {other_flow_id} and {flow_id}")
                result = (Comparator.equal, other_flow_id, flow_id)
            else:
                logging.info(f"Replayed request with different responses: {other_flow_id} and {flow_id}")
                result = (Comparator.different, other_flow_id, flow_id)
        
        return result

class Duplicator:
    def __init__(self):
        self.flow_storage = FlowStorage()
        self.comparator = Comparator(self.flow_storage)
        self.not_replayed: dict[str, None] = {}

        # Instead of setting options through command line, load them using the auth-test.yaml file
        self.cookies = []
        self.headers = []
        self.domains = []
        self.load_options()
    
    def load_options(self):
        try:
            with open('auth-test.yaml', 'r') as file:
                logging.info("[*] Reading auth-test.yaml file")
                lines = file.readlines()

                data = {
                    'Cookies': [],
                    'Headers': [],
                    'Domains': [],
                }
                
                state_machine = ''
                for line in lines:
                    if line.startswith('# Cookies'):
                        state_machine = 'Cookies'
                        continue
                    elif line.startswith('# Headers'):
                        state_machine = 'Headers'
                        continue
                    elif line.startswith('# Domains'):
                        state_machine = 'Domains'
                        continue
                    elif line.startswith('#') or line.strip() == '':
                        continue

                    data[state_machine].append(line.strip())
                
                self.cookies = data['Cookies']
                self.headers = data['Headers']
                self.domains = data['Domains']

                logging.info(f"[*] Loaded Cookies: {self.cookies}")
                logging.info(f"[*] Loaded Headers: {self.headers}")
                logging.info(f"[*] Loaded Domains: {self.domains}")

        except FileNotFoundError:
            logging.error("[!] auth-test.yaml file not found")

    def request(self, flow: http.HTTPFlow):
        replay_request = False
        for domain in self.domains:
            if domain in flow.request.host:
                replay_request = True
                break
        if not replay_request:
            self.not_replayed[flow.id] = None
            return

        raw_request = assemble.assemble_request(flow.request)
        self.flow_storage.put_raw_request(flow.id, raw_request)

        # Avoid an infinite loop by not replaying already replayed requests
        if flow.is_replay == "request":
            return
        
        flow_id = flow.id
        flow = flow.copy()
        copied_flow_id = flow.id
        self.comparator.add_pair(flow_id, copied_flow_id)

        # Only interactive tools have a view. If we have one, add a duplicate entry
        # for our flow
        if "view" in ctx.master.addons:
            ctx.master.commands.call("view.flows.duplicate", [flow])
        
        # Remove cookies from the duplicated request
        for cookie in self.cookies:
            flow.request.cookies.pop(cookie, None)

        # Remove headers from the duplicated request
        for header in self.headers:
            flow.request.headers.pop(header, None)

        ctx.master.commands.call("replay.client", [flow])
    
    def response(self, flow: http.HTTPFlow):
        if flow.id in self.not_replayed:
            del self.not_replayed[flow.id]
            return

        if flow.response and flow.response.content:
            raw_response_headers = assemble.assemble_response_head(flow.response)
            raw_response = raw_response_headers + flow.response.content
            self.flow_storage.put_raw_response(flow.id, raw_response)

            result, flow_id1, flow_id2 = self.comparator.add_content(flow.id, flow.response.content, flow.response.status_code)

            dir_name = ''
            file_name = flow_id1 + '--' + flow_id2
            ext = '.req'
            
            if result == Comparator.undefined:
                return
            elif result == Comparator.equal:
                dir_name = 'flows/equal/'
            elif result == Comparator.different:
                dir_name = 'flows/different/'

            with open(dir_name + file_name + ext, 'wb') as file:
                    request1 = self.flow_storage.pop(flow_id1)
                    request2 = self.flow_storage.pop(flow_id2)
                    sep = b'\r\n' + b'-'*80 + b'\r\n\r\n'
                    file.write(request1 + sep + request2)

# Create log directories if they not exist
os.makedirs('flows/different', exist_ok=True)
os.makedirs('flows/equal', exist_ok=True)

addons = [Duplicator()]