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
import psycopg2

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from core.MalwasmConfig import *
from core.MalwasmConstants import *

def connect_db(config):
    """Returns a new connection to the database."""
    return psycopg2.connect("dbname=%s user=%s password=%s host=%s" %
        (config['dbname'], config['username'], 
        config['password'], config['host']))

def build_xml(db, sample_id, folder_path):
    filepath = os.path.join(folder_path, 'malwpin.xml')
    fp = open(filepath, 'w')
    fp.write("<info>")
    cur = db.cursor('cursor_ins')
    #cur = db.cursor('cursor_ins', cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT i.id, i.thread_id, asm, name, comment, eax, ebx, " + \
            "ecx, edx, edi, esi, ebp, esp, eip, eflags "
            "FROM ins i " + \
            "INNER JOIN reg r ON i.id=r.ins_id AND r.sample_id=i.sample_id " + \
            "AND r.thread_id=i.thread_id " + \
            "WHERE i.sample_id=%s", (sample_id,))

    for r in cur:
        data = []
        for x in r:
            c = '' if x is None else x
            data.append(c)

        s = "<ins>" + \
        "<id>%s</id>" + \
        "<thread>%s</thread>" + \
        "<asm>%s</asm>" + \
        "<name>%s</name>" + \
        "<comment>%s</comment>" + \
        "<reg>" + \
            "<eax>%s</eax>" + \
            "<ebx>%s</ebx>" + \
            "<ecx>%s</ecx>" + \
            "<edx>%s</edx>" + \
            "<edi>%s</edi>" + \
            "<esi>%s</esi>" + \
            "<ebp>%s</ebp>" + \
            "<esp>%s</esp>" + \
            "<eip>%s</eip>" + \
            "<eflags>%s</eflags>" + \
        "</reg></ins>\n" 
        s = s % tuple(data)

        fp.write(s)

    cur.close()
    cur = db.cursor('cursor_ins')

    cur.execute("SELECT ins_id, thread_id, adr_start, adr_stop, cur " + \
            "FROM dump " + \
            "WHERE sample_id=%s",
            (sample_id,));

    for r in cur:
        s = "<data>" + \
            "<id>%s</id>" + \
            "<thread>%s</thread>" + \
            "<start>%s</start>" + \
            "<end>%s</end>" + \
            "<cur>%s</cur>" + \
            "</data>\n"

        s = s % tuple(r)
        fp.write(s)
    fp.close()

    cur.close()

    cur = db.cursor('cursor_ins2')

    cur.execute("SELECT filename, md5, pin_param FROM sample WHERE id=%s",
            (sample_id,))

    s = cur.fetchone()
    
    xml_sample = "<sample>" + \
        "<filename>%s</filename>" + \
        "<md5>%s</md5>" + \
        "<pin_param>%s</pin_param>" + \
        "</sample>" 
    xml_sample = xml_sample % tuple(s)

    open(os.path.join(folder_path, 'sample.xml'), 'w').write(xml_sample)
    cur.close()


def build_dump(db, sample_id, folder_path):
    cur = db.cursor('cursor_ins')
    cur.execute("select ins_id, thread_id, adr_start, data " + \
            "from dump " + \
            "where sample_id=%s" ,
            (sample_id,));

    for r in cur:
        filename = os.path.join(folder_path, 
                "data_%s_%s_%d.dmp" % (r[0], r[1], r[2]))
        fp = open(filename, 'w')
        fp.write(str(r[3]))
        fp.close()

    cur.close()
    

def main():
    parser = argparse.ArgumentParser(description = 'Malwasm insert XML into DB')
    parser.add_argument('--version', action='version', 
        version="%(prog)s version " + MALWASM_VERSION)
    
    # software configuration required param
    parser.add_argument('-d', '--dir', action='store', required=True,
        help='Directory where generated data are stocked')
    parser.add_argument('-i', '--sample-id', action='store', required=True,
        help='Sample id')
    
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
        c = connect_db(config)
        try: 
            os.mkdir(r.dir)
        except:
            pass
        path_memory = os.path.join(r.dir, "memory")
        try:
            os.mkdir(path_memory)
        except:
            pass


        build_xml(c, r.sample_id, r.dir)
        build_dump(c, r.sample_id, path_memory)
        c.close() 
        ret = os.EX_OK
    except Exception as e:
        logging.exception(e)
        print >> sys.stderr, e

    sys.exit(ret)

if __name__ == '__main__':
    main()
