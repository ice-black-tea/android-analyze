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
        self.dir = os.path.join(os.path.expanduser('~'), ".frida")
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)
        self.path = os.path.join(self.dir, self.name)
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
        utils.exec_shell("adb forward tcp:27042 tcp:27042")
        utils.exec_shell("adb forward tcp:27043 tcp:27043")
        utils.exec_shell("adb push '{0}' /data/local/tmp/".format(fsf.path))
        utils.exec_shell("adb shell \"chmod 755 '{0}'\"".format(fsf.target_path))
        if utils.get_adb_shell_uid() == 0:
            commond = "'{0}'".format(fsf.target_path)
        else:
            commond = "su -c '{0}'".format(fsf.target_path)
        system_name = platform.system()
        if system_name == "Linux" or system_name == "Darwin":
            utils.exec_shell("adb shell \"{0}\" &".format(commond))
        elif system_name == "Windows":
            utils.exec_shell("start /b adb shell \"{0}\"".format(commond))
        else:
            raise Exception('not yet implemented')
        time.sleep(1)

    @staticmethod
    def __is_running(fsf: frida_server_file):
        process = utils.exec_shell("adb shell \"ps | grep {0}\"".format(fsf.name), True, True)
        return fsf.name in process.out

if __name__ == '__main__':
    frida_server.start()
