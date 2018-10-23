#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import frida

import tempfile
import lzma
import shutil
import platform
import time

from .utils import utils

class frida_server_file:

    def __init__(self, version, abi):
        self.name = "frida-server-{0}-android-{1}".format(version, abi)
        self.path = "{0}/.frida/{1}".format(os.path.expanduser('~'), self.name)
        self.url = "https://github.com/frida/frida/releases/download/{0}/{1}.xz".format(version, self.name)
        self.target_path = "/data/local/tmp/{0}".format(self.name)

class frida_server:

    @staticmethod
    def start():
        """ 下载并运行frida server """
        version = frida.__version__
        abi = utils.get_device_abi()
        if (abi is None):
            return
        fsf = frida_server_file(version, abi)
        if (frida_server.__is_running(fsf)):
            print("[*] Frida server is running ...")
        else:
            print("[*] Frida server is not running, now start frida server ...")
            frida_server.__start(fsf)
            if (frida_server.__is_running(fsf)):
                print("[*] Frida server is running ...")
            else:
                print("[*] Frida server failed to run ...")

    @staticmethod
    def is_running():
        """ 是否已经运行了frida server """
        version = frida.__version__
        abi = utils.get_device_abi()
        if (abi is None):
            return False
        fsf = frida_server_file(version, abi)
        return frida_server.__is_running(sfs)

    @staticmethod
    def __start(fsf: frida_server_file):
        if (not os.path.exists(fsf.path)):
            tmp_path = tempfile.mktemp()
            utils.download_from_url(fsf.url, tmp_path)
            with lzma.open(tmp_path, "rb") as read, open(fsf.path, "wb") as write:
                shutil.copyfileobj(read, write)
            os.remove(tmp_path)
        log_prefix = "/sdcard/frida_server_log_"
        log_path = "{0}{1}".format(log_prefix, time.time())
        utils.exec_shell("adb forward tcp:27042 tcp:27042", stdout=None, stderr=None)
        utils.exec_shell("adb forward tcp:27043 tcp:27043", stdout=None, stderr=None)
        utils.exec_shell("adb push '{0}' /data/local/tmp/".format(fsf.path), stdout=None, stderr=None)
        utils.exec_shell("adb shell \"chmod 755 '{0}' >'{1}' 2>&1\"".format(fsf.target_path, log_path), stdout=None, stderr=None)
        utils.exec_shell("adb shell \"su -l -c nohup '{0}' >>'{1}' 2>&1 &\"".format(fsf.target_path, log_path), stdout=None, stderr=None)
        time.sleep(1)
        utils.exec_shell("adb shell \"cat '{0}'\"".format(log_path), stdout=None, stderr=None)
        utils.exec_shell("adb shell \"rm -f {0}*\"".format(log_prefix), stdout=None, stderr=None)

    @staticmethod
    def __is_running(fsf: frida_server_file):
        process, out, err = utils.exec_shell("adb shell \"ps | grep {0}\"".format(fsf.name))
        if (process is not None):
            return fsf.name in out
        print(err if not None else out)
        return False

if __name__ == '__main__':
    frida_server.start()
