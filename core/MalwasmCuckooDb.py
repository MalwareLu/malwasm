#!/usr/bin/env python2.7
# Copyright (C) 2012 Malwasm Developers.
# This file is part of Malwasm - https://code.google.com/p/malwasm/
# See the file LICENSE for copying permission.
#                  _                             
#  _ __ ___   __ _| |_      ____ _ ___ _ __ ___  
# | '_ ` _ \ / _` | \ \ /\ / / _` / __| '_ ` _ \ 
# | | | | | | (_| | |\ V  V / (_| \__ \ | | | | |
# |_| |_| |_|\__,_|_| \_/\_/ \__,_|___/_| |_| |_|
#

import sys
import os

from core.MalwasmConfig import MalwasmConfig
cuckoo_path = os.path.expanduser(MalwasmConfig().get('cuckoo')['cuckoo_path'])
sys.path.append(cuckoo_path)
from lib.cuckoo.core.database import Database

class MalwasmCuckooDb(Database):
    def is_complete(self, task_id):
        """Return if a task is finish.
         @param task_id: task id.
         @return: true if a task is complete.
        """
        try:
           self.cursor.execute("SELECT status FROM tasks WHERE id = ?;",
               (task_id,))
           row = self.cursor.fetchone()
        except sqlite3.OperationalError as e:
           return False
        return row['status'] != 0
