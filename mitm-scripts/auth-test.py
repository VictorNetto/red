"""
Take incoming HTTP requests having specifieds headers/cookies and replay them
without these headers/cookies. The script also compare the reponse to find
possible diferences indicating the lack of proper authentication.
"""

from collections.abc import Sequence
import logging

from mitmproxy import ctx
from mitmproxy import http
from mitmproxy import addonmanager
from mitmproxy.net.http.http1 import assemble

class Storage:
    def __init__(self):
        self.storage = {}
    
    def put_request(self, id, data):
        self.storage[id] = data

    def put_response(self, id, data):
        self.storage[id] += data

    def pop(self, id):
        return self.storage.pop(id)

class Comparator:
    undefined = -1
    equal = 0
    different = 1

    def __init__(self):
        self.pairs = {}
        self.content = {}
    
    def add_pair(self, p1, p2):
        self.pairs[p1] = p2
        self.pairs[p2] = p1
    
    def add_content(self, p1, p1_content):
        self.content[p1] = p1_content

        p2 = self.pairs.get(p1)
        p2_content = self.content.get(p2)

        result = (Comparator.undefined, p1, p2)
        if p2_content is not None:
            if p1_content == p2_content:
                logging.warning(f"Replayed request with equal responses: {p1} and {p2}")
                result = (Comparator.equal, p1, p2)
            else:
                logging.info(f"Replayed request with different responses: {p1} and {p2}")
                result = (Comparator.different, p1, p2)
            
            del self.pairs[p1]
            del self.pairs[p2]
            del self.content[p1]
            del self.content[p2]
        
        return result

class Duplicator:
    def __init__(self):
        self.storage = Storage()
        self.comparator = Comparator()

    def load(self, loader: addonmanager.Loader):
        loader.add_option(
            name="cookie_name",
            typespec=Sequence[str],
            default=[],
            help="Cookie to remove when replaying requests"
        )

        loader.add_option(
            name="header_name",
            typespec=Sequence[str],
            default=[],
            help="Header to remove when replaying requests"
        )

    def request(self, flow: http.HTTPFlow):
        raw_request = assemble.assemble_request(flow.request)
        self.storage.put_request(flow.id, raw_request)

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
        for cookie in ctx.options.cookie_name:
            flow.request.cookies.pop(cookie, None)

        # Remove headers from the duplicated request
        for header in ctx.options.header_name:
            flow.request.headers.pop(header, None)

        ctx.master.commands.call("replay.client", [flow])
    
    def response(self, flow: http.HTTPFlow):
        if flow.response and flow.response.content:
            raw_response = assemble.assemble_response(flow.response)
            self.storage.put_response(flow.id, raw_response)

            result, flow_id1, flow_id2 = self.comparator.add_content(flow.id, hash(flow.response.content))

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
                    request1 = self.storage.pop(flow_id1)
                    request2 = self.storage.pop(flow_id2)
                    sep = b'\r\n' + b'-'*80 + b'\r\n\r\n'
                    file.write(request1 + sep + request2)

addons = [Duplicator()]