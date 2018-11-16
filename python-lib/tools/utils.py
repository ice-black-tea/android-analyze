#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

import subprocess

import requests
import warnings
from urllib.request import urlopen
from tqdm import tqdm, TqdmSynchronisationWarning

import tempfile
import lzma
import shutil

class shell_process(subprocess.Popen):

    def __init__(self, cmd, capture_out=False, capture_err=False):
        self.out = ""
        self.err = ""
        self.returncode = -888
        try:
            stdout = subprocess.PIPE if capture_out else None
            stderr = subprocess.PIPE if capture_err else None
            subprocess.Popen.__init__(self, cmd, shell=True, \
                stdout=stdout, stderr=stderr)
            out, err = self.communicate()
            if out is not None:
                self.out = self.out + out.decode(errors='ignore')
            if err is not None:
                self.err = self.err + err.decode(errors='ignore')
        except Exception as e:
            self.err = self.err + str(e)

    def __str__(self):
        result = ""
        for key,value in sorted(self.__dict__.items()):
            if not key.startswith("_"):
                result = result + "{0}: {1}\r\n".format(key, value)
        return result

class utils:

    @staticmethod
    def is_empty(string):
        return string is None or len(string) == 0

    @staticmethod
    def exec_shell(cmd, capture_out=False, capture_err=False):
        """ 执行shell """
        return shell_process(cmd, capture_out, capture_err)

    @staticmethod
    def exec_adb_shell(cmd, capture_out=False, capture_err=False):
        """执行adb shell"""
        return utils.exec_shell("adb shell " + cmd, capture_out, capture_err)

    @staticmethod
    def get_device_abi():
        """ 获取设备abi """
        process = utils.exec_adb_shell("getprop ro.product.cpu.abi", True, True)
        if (process.returncode != 0):
            print(process.err)
            return None
        if (process.out.find("arm64") >= 0):
            return "arm64"
        elif (process.out.find("armeabi") >= 0):
            return "arm"
        elif (process.out.find("x86_64") >= 0):
            return "x86_64"
        elif (process.out.find("x86") >= 0):
            return "x86"
        print(process.err if not None else process.out)
        return None

    @staticmethod
    def get_adb_uid():
        """ 获取shell的uid """
        try:
            return int(utils.exec_adb_shell("id -u", True, True).out)
        except:
            return -1

    @staticmethod
    def download_from_url(url, file_path):
        """
        从url下载文件
            url(str):           下载链接
            file_path(str):     下载路径
        """
        file_dir = os.path.dirname(file_path)
        if (not os.path.exists(file_dir)):
            os.makedirs(file_dir)
        if (os.path.exists(file_path)):
            first_byte = os.path.getsize(file_path)
        else:
            first_byte = 0
        file_size = int(urlopen(url).info().get('Content-Length', -1))
        if first_byte >= file_size:
            return file_size
        header = {"Range": "bytes=%s-%s" % (first_byte, file_size)}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", TqdmSynchronisationWarning)
            pbar = tqdm(total=file_size, initial=first_byte,
                unit='B', unit_scale=True, desc=url.split('/')[-1])
            req = requests.get(url, headers=header, stream=True)
            with (open(file_path, 'ab')) as f:
                for chunk in req.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        pbar.update(1024)
            pbar.close()
        return file_size
