import sys
import logging

from mitmproxy import addonmanager

class Args:
    def load(self, _: addonmanager.Loader):
        logging.info(sys.argv)

addons = [Args()]