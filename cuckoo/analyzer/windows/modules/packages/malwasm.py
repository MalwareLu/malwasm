# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os
from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.paths import PATHS

class Exe(Package):
    """Malwasm EXE analysis package."""

    def start(self, path):
        p = Process()
        pin = os.path.join("bin", "pin.exe")
        dll = os.path.join("bin", "malwpin.dll")

        if "share_letter" in self.options:
            root = self.options['share_letter']
        else:
            root = "E:\\" #PATHS["root"]

        out = os.path.join(root, "malwpin.xml")
        pinlog = os.path.join(root, "pin.log")
        stack_dir = os.path.join(root, "memory") + os.sep

        pin_arg = ""
        if "adr-start" in self.options:
            pin_arg += " -adr-start %s " % self.options['adr-start']

        if "adr-stop" in self.options:
            pin_arg += " -adr-stop %s " % self.options['adr-stop']
        
        if "n" in self.options:
            pin_arg += " -n %s " % self.options['n']

        argv = "-t %s -o %s -s %s -logfile %s %s -- %s" % (dll, out, stack_dir, pinlog, pin_arg, path)
        #argv = "-t %s -o %s -s %s -logfile %s -follow_execv -- %s" % (dll, out, stack_dir, pinlog, path)

        if "arguments" in self.options:
            argv += " " + self.options["arguments"]

        p.execute(path=pin, args=argv, suspended=True)

        #inject = True
        #if "free" in self.options:
            #if self.options["free"] == "yes":
                #inject = False

        #if inject:
            #p.inject()

        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
