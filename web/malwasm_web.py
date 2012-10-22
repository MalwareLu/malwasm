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

import psycopg2
import psycopg2.extras
import json, StringIO
import sys, os
import datetime
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash, jsonify, send_file

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from core.MalwasmConfig import *

# Debug flag
DEBUG = True

# Db config from MalwasmConfig
config = MalwasmConfig().get('database')

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

def connect_db():
    """Returns a new connection to the database."""
    return psycopg2.connect("dbname=%s user=%s password=%s host=%s" %
        (config['dbname'], config['username'], 
        config['password'], config['host']))

@app.before_request
def before_request():
    """Make sure we are connected to the database each request."""
    g.db = connect_db()


@app.teardown_request
def teardown_request(exception):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'db'):
        g.db.close()

@app.route('/nthreads')
def nthreads():
    """ Return the number of thread used by a samples
    """
    sample_id = request.args.get('sample_id', -1, type=int)
    if sample_id == -1:
        abort(401)
    
    cur = g.db.cursor()
    cur.execute("SELECT DISTINCT thread_id FROM ins WHERE sample_id=%s",(sample_id,))

    d = cur.fetchall()
    threads=[]
    for t in d:
        threads.append(t[0])
    cur.close()
    threads.sort()
    return json.dumps(threads)
    
@app.route('/dump')
def dump():
    """
    Return dump of memory for a sample_id, an ins_id, a thread_id
    and a address range
    """
    sample_id = request.args.get('sample_id', -1, type=int)
    ins_id = request.args.get('ins_id', -1, type=int)
    thread_id = request.args.get('thread_id', -1, type=int)
    adr_start = request.args.get('start', -1, type=int)
    adr_stop = request.args.get('stop', -1, type=int)
    if sample_id == -1 or ins_id == -1 or thread_id == -1 or adr_start == -1\
            or adr_stop == -1:
        abort(401)
    cur = g.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT data, adr_start " + \
                "FROM dump " + \
                "WHERE sample_id=%s AND ins_id<=%s AND thread_id=%s " + \
                    "AND adr_start<=%s AND adr_stop>=%s"
                "ORDER BY ins_id DESC LIMIT 1",
                (sample_id, ins_id, thread_id, adr_start, adr_stop));
    d = cur.fetchone()
    if d == None:
        return '', 404

    cur.close()
    output = StringIO.StringIO()
    output.write(d['data'][ adr_start-d['adr_start'] : adr_stop-d['adr_start'] ])
    output.seek(0)
    return send_file(output)

@app.route('/instruction')
def instruction():
    """Return a instruction information for a sample_id and ins_id"""
    sample_id = request.args.get('sample_id', -1, type=int)
    ins_id = request.args.get('ins_id', -1, type=int)
    thread_id = request.args.get('thread_id', -1, type=int)
    if sample_id == -1 or ins_id == -1 or thread_id == -1:
        abort(401)

    cur = g.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM ins i " +\
        "INNER JOIN reg r ON id=ins_id  AND r.sample_id=i.sample_id AND i.thread_id=r.thread_id " +\
        "WHERE i.sample_id=%s AND ins_id=%s AND i.thread_id=%s", 
        (sample_id, ins_id, thread_id))
    d = cur.fetchone()
    cur.close()
    return json.dumps(d)

@app.route('/samples')
def samples():
    """Return all samples information"""
    cur = g.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    dthandler = lambda obj: obj.strftime('%Y-%m-%d %H:%M:%S') if isinstance(obj, datetime.datetime) else None
    cur.execute("SELECT id, filename, md5, insert_at, pin_param FROM sample ORDER BY id DESC;")
    d = cur.fetchall()
    cur.close()
    return json.dumps(d,  default=dthandler)

@app.route('/threadInfo')
def threadInfo():
    """Return all information about thread_id of a sample_id"""
    sample_id = request.args.get('sample_id', -1, type=int)
    thread_id = request.args.get('thread_id', -1, type=int)
    if sample_id == -1 or thread_id == -1:
        abort(401)

    # build information instruction
    cur = g.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT f.name[1] as filename, f.name[2] as section, f.adr " + \
                "FROM ( " + \
                    "SELECT DISTINCT regexp_matches(name, '^(.*):([^\+]*)(.*)?$') as name, adr "+ \
                    "FROM ins WHERE sample_id=%s AND thread_id=%s) " + \
                "AS f ORDER BY adr", (sample_id,thread_id))
    d = cur.fetchall()
    results = {}
    results['tree'] = {}
    for r in d:
        if r['filename'] not in results['tree']:
            results['tree'][r['filename']]={}
        if r['section'] not in results['tree'][r['filename']]:
            results['tree'][r['filename']][r['section']]=[]
        results['tree'][r['filename']][r['section']].append(r['adr'])
    cur.execute("SELECT adr, id, asm, name, comment FROM ins WHERE sample_id=%s AND thread_id=%s ORDER BY adr, id", (sample_id,thread_id))
    d = cur.fetchall()
    results['instruction'] = {}
    for i in d:
        if i['adr'] not in results['instruction']:
            results['instruction'][i['adr']]={}
        results['instruction'][i['adr']][i['id']]={'name' : i['name'],
                                            'asm' : i['asm'],
                                            'comment': i['comment']}
    cur.execute("SELECT adr_start, adr_stop, MIN(ins_id) AS min_ins_id " + \
                "FROM dump WHERE sample_id=%s AND thread_id=%s " + \
                "GROUP BY adr_start, adr_stop " + \
                "ORDER BY adr_start ASC", (sample_id, thread_id)) ;
    memRange = cur.fetchall()
    results['memRange']=[]
    for r in memRange:
        cur.execute("SELECT ins_id, adr_start, adr_stop " + \
                "FROM dump WHERE sample_id=%s AND thread_id=%s " + \
                "AND adr_start=%s AND adr_stop=%s"  + \
                "ORDER BY ins_id", (sample_id, thread_id, r['adr_start'], r['adr_stop']));
        r['list'] = cur.fetchall()
        results['memRange'].append(r)
    return json.dumps(results)

@app.route('/')
def index():
    return render_template('index.html') 

if __name__ == '__main__':
    app.run()
