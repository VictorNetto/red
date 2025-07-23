import logging

from mitmproxy import http

class Redirec:
    count = -1
    period = 10

    def request(self, flow: http.HTTPFlow):
        if flow.request.scheme != "http":
            return
        
        self.count += 1
        logging.warn(self.count)
        if self.count % self.period == 0:
            flow.response = http.Response.make(
                302,
                b"",
                { "Location": "https://bb.com.br", "Content-length": "0" }
            )

        elif self.count % self.period == 1:
            flow.response = http.Response.make(
                302,
                b"",
                { "Location": "http://bb.com.br:80", "Content-length": "0" }
            )

addons = [Redirec()]