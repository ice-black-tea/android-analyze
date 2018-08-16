#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import frida

import tempfile
import lzma
import shutil

from .utils import utils

class frida_server:
    @staticmethod
    def start_server():
        """ 下载并运行frida server """
        version = frida.__version__
        abi = utils.get_device_abi()
        if (abi is None):
            return
        file_name = "frida-server-{0}-android-{1}".format(version, abi)
        file_path = "{0}/.frida/{1}".format(os.path.expanduser('~'), file_name)
        if (not os.path.exists(file_path)):
            url = "https://github.com/frida/frida/releases/download/{0}/{1}.xz".format(version, file_name)
            tmp_path = tempfile.mktemp()
            utils.download_from_url(url, tmp_path)
            with lzma.open(tmp_path, "rb") as read, open(file_path, "wb") as write:
                shutil.copyfileobj(read, write)
            os.remove(tmp_path)
        utils.exec_shell("adb forward tcp:27042 tcp:27042", stdout=None, stderr=None)
        utils.exec_shell("adb forward tcp:27043 tcp:27043", stdout=None, stderr=None)
        utils.exec_shell("adb push {0} /data/local/tmp/".format(file_path), stdout=None, stderr=None)
        utils.exec_adb_shell("chmod 755 /data/local/tmp/{0}".format(file_name), stdout=None, stderr=None)
        utils.exec_adb_shell("/data/local/tmp/{0}".format(file_name), stdout=None, stderr=None)

if __name__ == '__main__':
    frida_server.start_server()
