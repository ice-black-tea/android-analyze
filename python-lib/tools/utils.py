#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

import subprocess

import requests
import warnings
from urllib.request import urlopen
from tqdm import tqdm, TqdmSynchronisationWarning

import tempfile
import lzma
import shutil

class utils:
    @staticmethod
    def exec_shell(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
        """ 执行shell """
        try:
            process = subprocess.Popen(cmd, shell=True, stdout=stdout, stderr=stdout)
        except Exception as e:
            return None, "", e.message
        out, err = process.communicate()
        out = out.decode(errors='ignore') if out else ""
        err = err.decode() if err else ""
        return process, out, err

    @staticmethod
    def exec_adb_shell(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
        """执行adb shell"""
        return utils.exec_shell("adb shell " + cmd, stdout=stdout, stderr=stderr)

    @staticmethod
    def get_device_abi():
        """ 获取设备abi """
        process, out, err = utils.exec_adb_shell("getprop ro.product.cpu.abi")
        if (process is None):
            print(err)
            return None
        if (out.find("arm64") >= 0):
            return "arm64"
        elif (out.find("armeabi") >= 0):
            return "arm"
        elif (out.find("x86_64") >= 0):
            return "x86_64"
        elif (out.find("x86") >= 0):
            return "x86"
        print(err if not None else out)
        return None

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
