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

MALWASM_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))
MALWASM_DB_SCHEMA = os.path.join(MALWASM_ROOT, "conf", "schema.sql")
MALWASM_VERSION = "0.1"
