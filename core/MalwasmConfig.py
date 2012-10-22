#!/usr/bin/env python2.7
# Copyright (C) 2012 Malwasm Developers.
# This file is part of Malwasm - https://code.google.com/p/malwasm/
# See the file LICENSE for copying permission.
#                  _                             
#  _ __ ___   __ _| |_      ____ _ ___ _ __ ___  
# | '_ ` _ \ / _` | \ \ /\ / / _` / __| '_ ` _ \ 
# | | | | | | (_| | |\ V  V / (_| \__ \ | | | | |
# |_| |_| |_|\__,_|_| \_/\_/ \__,_|___/_| |_| |_|

import os
import ConfigParser

from core.MalwasmConstants import MALWASM_ROOT

class MalwasmConfig():
    def __init__(self, cfg=os.path.join(MALWASM_ROOT, "conf", "malwasm.conf")):
        """@param cfg: configuration file path."""
        config = ConfigParser.ConfigParser()
        config.read(cfg)

        self.section = {}
        for section in config.sections():
            self.section[section] = {}
            for name, raw_value in config.items(section):
                try:
                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)

                self.section[section][name] = value

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @return: option value.
        """
        return self.section[section]
