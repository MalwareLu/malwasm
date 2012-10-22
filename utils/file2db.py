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
# postgres python module
# sudo apt-get install python-psycopg2

import logging
import argparse, re, sys, os

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from core.MalwasmDb import *
from core.MalwasmConfig import *
from core.MalwasmConstants import *

def main():
    parser = argparse.ArgumentParser(description = 'Malwasm insert XML into DB')
    parser.add_argument('--version', action='version', 
        version="%(prog)s version " + MALWASM_VERSION)
    
    # software configuration required param
    #parser.add_argument('-e', '--exe', action='store', required=True,
        #help='Sample file related to the data')
    parser.add_argument('-d', '--dir', action='store', required=True,
        help='Directory where generated data are stocked')
    #parser.add_argument('--pin-param', action='store', default="",
        #help='Directory where generated data are stocked')
    
    config = MalwasmConfig().get('database')

    # database configuration
    parser.add_argument('-u', '--username', action='store', 
        default=config['username'], help='Database username')
    parser.add_argument('-p', '--password', action='store', 
        default=config['password'], help='Database password')
    parser.add_argument('--db', action='store', 
        default=config['dbname'], help='Database name')
    parser.add_argument('--host', action='store', 
        default=config['host'], help='Database hostname')
    
    # logging configuration
    parser.add_argument('--debug', action='store_const', const=logging.DEBUG,
        default=logging.INFO, dest='logging', help='Show debug output')

    # parse cli argument
    r = parser.parse_args()

    logging.basicConfig(level=r.logging)
    
    # build the new configuration
    c = {
        'username': r.username,
        'password': r.password,
        'dbname': r.db,
        'host': r.host,
    }
    config.update(c)

    ret = os.EX_SOFTWARE
    try:
        m = MalwasmDb(config)
        m.insert(r.dir)
        ret = os.EX_OK
    except MalwasmExceptDbConn as e:
        print >> sys.stderr, "Database connection error:", e
    except MalwasmExceptDb as e:
        print >> sys.stderr, "Database error:", e
    except Exception as e:
        logging.exception(e)
        print >> sys.stderr, e

    sys.exit(ret)

    conn.close()

    sys.exit(os.EX_OK)

if __name__ == '__main__':
    main()
