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


class Duplicator:
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
        logging.warning(f"IMHERE {flow.id}")

        # Avoid an infinite loop by not replaying already replayed requests
        if flow.is_replay == "request":
            return
        
        flow = flow.copy()

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
            logging.warning(len(flow.response.content))
        logging.warning(f"ANDHERE {flow.id}")


addons = [Duplicator()]