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

import logging
import argparse, re, sys, os
import time
import shutil

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from core.MalwasmDb import *
from core.MalwasmCuckooDb import *
from core.MalwasmConstants import *
from core.MalwasmConfig import *
from datetime import date

from lib.cuckoo.common.objects import File


def main():
    parser = argparse.ArgumentParser(description = 'Malwasm submit samples')
    parser.add_argument('--version', action='version', 
        version="%(prog)s version " + MALWASM_VERSION)
    parser.add_argument("--custom", type=str, 
        action="store", default="", 
        help="Specify any custom value", required=False)
    parser.add_argument("--timeout", type=int, 
        action="store", default=0, 
        help="Specify an analysis timeout", required=False)
    parser.add_argument("--options", type=str, 
        action="store", default="", 
        help="Specify options for the analysis package (e.g. \"name=value,name2=value2\")", required=False)
    parser.add_argument("--priority", type=int, 
        action="store", default=1, 
        help="Specify a priority for the analysis represented by an integer", required=False)
    parser.add_argument("--machine", type=str, 
        action="store", default="", 
        help="Specify the identifier of a machine you want to use", required=False)
    parser.add_argument("--platform", type=str, 
        action="store", default="", 
        help="Specify the operating system platform you want to use (windows/darwin/linux)", required=False)

    parser.add_argument("path", type=str, help="Path to the file to analyze")

    r = parser.parse_args()

    r.path = os.path.abspath(r.path)

    if not os.path.exists(r.path):
        print("ERROR: the specified file does not exist at path \"%s\"" % args.path)
        sys.exit(os.EX_USAGE)


    config = MalwasmConfig().get('cuckoo')
    sub_folder = str(time.time()).replace('.','')
    share_path = os.path.join(config['share_host_path'], sub_folder)
    print " [*] Use the following share_path %s..." % share_path

    os.mkdir(share_path)

    # Add the share letter parameter
    if r.options:
        pin_param = r.options
        r.options += ",share_letter=%s\\%s" % (config['share_vm_letter'], sub_folder)
    else:
        r.options = "share_letter=%s\\%s" % (config['share_vm_letter'], sub_folder)
        pin_param = ""
        
    xml_sample = "<sample>" + \
        "<filename>%s</filename>" + \
        "<md5>%s</md5>" + \
        "<pin_param>%s</pin_param>" + \
        "</sample>" 
    xml_sample = xml_sample % (os.path.basename(r.path), 
        File(r.path).get_md5(), pin_param)

    open(os.path.join(share_path, 'sample.xml'), 'w').write(xml_sample)
    db = MalwasmCuckooDb()

    task_id = db.add(File(r.path),
                     package="malwasm",
                     timeout=r.timeout,
                     options=r.options,
                     priority=r.priority,
                     machine=r.machine,
                     platform=r.platform,
                     custom=r.custom)
      
    print " [*] Task added with id %d in cuckoo" % task_id
    print " [*] Wait to task finish..."

    while db.get_status(task_id) != "success":
        time.sleep(1)

    print " [*] Task complete"
    print " [*] Insert into malwasm database..."

    ret = os.EX_SOFTWARE
    try:
        m = MalwasmDb()
        m.insert(share_path)
        ret = os.EX_OK
    except MalwasmExceptDbConn as e:
        print >> sys.stderr, "Database connection error:", e
    except MalwasmExceptDb as e:
        print >> sys.stderr, "Database error:", e
    except Exception as e:
        logging.exception(e)
        print >> sys.stderr, e

    print " [*] Job complete go on the web interface"
    
    sys.exit(ret)


if __name__ == '__main__':
    main()
