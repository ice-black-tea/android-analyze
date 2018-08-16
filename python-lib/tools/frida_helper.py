#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import frida

import threading
import subprocess

import colorama
from colorama import Fore, Back, Style

from .utils import utils

class frida_helper:
    """
    ----------------------------------------------------------------------

    eg.
        #!/usr/bin/env python3
        # -*- coding: utf-8 -*-

        from tools import frida_helper

        jscode = \"\"\"
        Java.perform(function () {
            var HashMap = Java.use("java.util.HashMap");
            HashMap.put.implementation = function() {
                return CallMethod(this, arguments, true, true);
            }
        });
        \"\"\"

        if __name__ == '__main__':
            frida_helper.run("com.hu.test", jscode=jscode, adb_shell="am start com.hu.test/.MainActivity")

    ----------------------------------------------------------------------

    js内置函数：

        /*
         * byte数组转字符串，如果转不了就返回byte[]
         * bytes:       字符数组
         * charset:     字符集(可选)
         */
        function BytesToString(bytes, charset);

        /*
         * 输出当前调用堆栈
         */
        function PrintStack();

        /*
         * 调用当前函数，并输出参数返回值
         * object:      对象(一般直接填this)
         * arguments:   arguments(固定填这个)
         * showStack:   是否打印栈(默认为false，可不填)
         * showArgs:    是否打印参数(默认为false，可不填)
         */
        function CallMethod(object, arguments, showStack, showArgs);

        /*
         * 打印栈，调用当前函数，并输出参数返回值
         * object:      对象(一般直接填this)
         * arguments:   arguments(固定填这个)
         * show:        是否打印栈和参数(默认为true，可不填)
         */
        function PrintStackAndCallMethod(object, arguments, show)

        /*
         * hook native
         */
        Interceptor.attach(Module.findExportByName(null, 'xxxxxx'), {
            onEnter: function (args) {
                send("xxxxxx called from:\\n" +
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\\n"));
            },
            onLeave: function (retval) {
                send("xxxxxx retval: " + retval);
            }
        });

        /*
         * 调用native函数
         * 例： CallStack callStack("ABCDEFG", 10);
         */
        var CallStackPtr = Module.findExportByName(null, '_ZN7android9CallStackC1EPKci');
        var CallStack = new NativeFunction(CallStackPtr, 'pointer', ['pointer', 'pointer', 'int']);
        var callStack = Memory.alloc(1000);
        var logtag = Memory.allocUtf8String("ABCDEFG");
        CallStack(callStack, logtag, 10);

    ----------------------------------------------------------------------
    """

    @staticmethod
    def kill(package_name):
        """
        结束进程
            package_name(str):  包名
        """
        utils.exec_adb_shell('am force-stop %s' % package_name, stdout=None, stderr=None)

    @staticmethod
    def run(package_name, jscode = "", process_name = "", adb_shell = ""):
        """
        运行js脚本
            package_name(str):  包名
            jscode(str):        js脚本
            process_name(str):  需要hook的进程名，不填则附加同一包名的所有进程
            adb_shell(str):     启动命令，如"am start -D xxx/.MainActivity"，填此命令会结束原有进程
        """

        colorama.init(True)
        jscode = frida_helper.__get_preset_jscode() + jscode
        if adb_shell != '':
            frida_helper.kill(package_name)
            utils.exec_adb_shell(adb_shell, stdout=None, stderr=None)
            for process in frida_helper.get_processes(package_name, process_name):
                print('[*] Attach process: %s (%d)' % (process.name, process.pid))
                session = frida_helper.get_device().attach(process.pid)
                script = session.create_script(jscode)
                script.on('message', frida_helper.__on_message)
                threading.Thread(target=frida_helper.__jdb_connect, args=(process.pid,)).start()
                script.load()
        else:
            for process in frida_helper.get_processes(package_name, process_name):
                print('[*] Attach process: %s (%d)' % (process.name, process.pid))
                session = frida_helper.get_device().attach(process.pid)
                script = session.create_script(jscode)
                script.on('message', frida_helper.__on_message)
                script.load()
        print('[*] Running ...')
        sys.stdin.read()

    @staticmethod
    def get_device():
        """ 获取设备 """
        return frida.get_remote_device()

    @staticmethod
    def get_processes(package_name, process_name = ""):
        """
        根据进程名获取进程，若进程名为空则匹配同一包名的所有进程
            package_name(str):  包名
            process_name(str):  进程名
        """
        processes = []
        if (process_name is None or not process_name.strip()):
            for process in frida_helper.get_device().enumerate_processes():
                if (process.name.find(package_name) > -1):
                    processes.append(process)
        else:
            process = frida_helper.get_device().get_process(process_name)
            processes.append(process.pid)
        return processes

    @staticmethod
    def jdb_connect(package_name, process_name = ""):
        """
        连接jdb，取消等待调试器附加状态
            package_name(str):  包名
            process_name(str):  进程名
        """
        for process in frida_helper.get_processes(package_name, process_name):
            frida_helper.__jdb_connect(process.pid)

    @staticmethod
    def __jdb_connect(pid):
        subprocess.call(['adb', 'forward', 'tcp:8700', 'jdwp:' + str(pid)])
        child = subprocess.Popen( \
            ['jdb', '-connect', 'com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700'], \
            stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = None)
        child.communicate()
        try:
            child.kill()
        finally:
            pass

    @staticmethod
    def __format(tag, message):
        return '[{0}] {1}'.format(tag, str(message).replace('\n', '\n    '))

    @staticmethod
    def __contain(obj, key):
        return obj is not None and isinstance(obj, dict) and key in obj

    @staticmethod
    def __on_message(message, data):
        if frida_helper.__contain(message, 'type') and message['type'] == 'send' and frida_helper.__contain(message, 'payload'):
            payload = message['payload']
            if frida_helper.__contain(payload, 'frida_stack'):
                print(Fore.LIGHTYELLOW_EX + frida_helper.__format("*", payload['frida_stack']))
            elif frida_helper.__contain(payload, 'frida_method'):
                print(Fore.LIGHTMAGENTA_EX + frida_helper.__format("*", payload['frida_method']))
            else:
                print(frida_helper.__format("*", payload))
        elif frida_helper.__contain(message, 'type') and message['type'] == 'error' and frida_helper.__contain(message, 'stack'):
            print(Fore.RED + frida_helper.__format("-", message['stack']))
        else:
            print(str(message))

    @staticmethod
    def __get_preset_jscode():
        return """
            var Throwable = null;
            var JavaString = null;
            var Charset = null;
            Java.perform(function () {
                Throwable = Java.use("java.lang.Throwable");
                JavaString = Java.use('java.lang.String');
                Charset = Java.use('java.nio.charset.Charset');
            });

            /*
             * byte数组转字符串，如果转不了就返回byte[]
             * bytes:       字符数组
             * charset:     字符集(可选)
             */
            function BytesToString(bytes, charset) {
                if (bytes !== undefined && bytes != null) {
                    charset = charset || Charset.defaultCharset();
                    var str = JavaString.$new.
                        overload('[B', 'java.nio.charset.Charset').
                        call(JavaString, bytes, charset).toString();
                    try {
                        return str.toString();
                    } catch(e) {
                        return null;
                    }
                } else {
                    return null;
                }
            }

            /*
             * 输出当前调用堆栈
             */
            function PrintStack() {
                __PrintStack(Throwable.$new().getStackTrace());
            };

            /*
             * 调用当前函数，并输出参数返回值
             * object:      对象(一般直接填this)
             * arguments:   arguments(固定填这个)
             * showStack:   是否打印栈(默认为false，可不填)
             * showArgs:    是否打印参数(默认为false，可不填)
             */
            function CallMethod(object, arguments, showStack, showArgs) {
                showStack = showStack === true;
                showArgs = showArgs === true;
                var stackElements = Throwable.$new().getStackTrace();
                __PrintStack(stackElements, showStack);
                return __CallMethod(stackElements[0], object, arguments, showArgs);
            };

            /*
             * 打印栈，调用当前函数，并输出参数返回值
             * object:      对象(一般直接填this)
             * arguments:   arguments(固定填这个)
             * show:        是否打印栈和参数(默认为true，可不填)
             */
            function PrintStackAndCallMethod(object, arguments, show) {
                return CallMethod(object, arguments, show !== false, show !== false);
            }

            function __PrintStack(stackElements, showStack) {
                if (!showStack) {
                    return;
                }
                var body = "Stack: " + stackElements[0];
                for (var i = 0; i < stackElements.length; i++) {
                    body += "\\n    at " + stackElements[i];
                }
                send({"frida_stack": body});
            }

            function __CallMethod(stackElement, object, arguments, showArgs) {
                var args = "";
                for (var i = 0; i < arguments.length; i++) {
                    args += "arguments[" + i + "],";
                }
                var method = stackElement.getMethodName();
                if (method == "<init>") {
                    method = "$init";
                }
                var ret = eval("object." + method + "(" + args.substring(0, args.length - 1) + ")");
                if (!showArgs) {
                    return ret;
                }
                var body = "Method: " + stackElement;
                for (var i = 0; i < arguments.length; i++) {
                    body += "\\n    Arguments[" + i + "]: " + arguments[i];
                }
                if (ret !== undefined) {
                    body += "\\n    Return: " + ret;
                }
                send({"frida_method": body});
                return ret;
            }
        """.replace("\n", "")
