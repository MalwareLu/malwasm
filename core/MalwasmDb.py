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

import psycopg2, psycopg2.errorcodes
import hashlib
import xml.parsers.expat
import logging
import argparse, re, sys, os
from progressbar import Bar, ETA, Percentage, ProgressBar

import xmltodict
from core.MalwasmConfig import *
from core.MalwasmConstants import *
from pprint import pprint 

# 'schema_filename': os.path.join(os.path.dirname(sys.argv[0]),'schema.sql'),

class MalwasmExceptDb(Exception):
    def __init__(self, value):
        self.value = value.strip('\n').split('\n')[0]
        logging.debug(value.strip('\n'))
    def __str__(self):
        return repr(self.value)

class MalwasmExceptDbExist(MalwasmExceptDb):
    pass

class MalwasmExceptDbNotExist(MalwasmExceptDb):
    pass

class MalwasmExceptDbConn(MalwasmExceptDb):
    pass

class MalwasmExceptXml(MalwasmExceptDb):
    pass

""" Manage db connection and create the malwasm database if not exist """
class MalwasmDb():

    """ Init the class and do the job """
    def __init__(self, config=MalwasmConfig().get('database')):
        self.conn = None
        self.c = config
        try:
            self.connect()
        except MalwasmExceptDbNotExist as e:
            self.generate()

    def __del__(self):
        self.close()

    """ Inchar to connect to the database """
    def connect(self):
        try:
            self.conn = psycopg2.connect("user='%s' password='%s' host='%s' dbname='%s'" %
                (self.c['username'], self.c['password'], 
                    self.c['host'], self.c['dbname']))
        except psycopg2.OperationalError as e:
            if re.search('database "(\w*)" does not exist',e.__str__()):
                raise MalwasmExceptDbNotExist(e.__str__())
            else:
                raise MalwasmExceptDbConn(e.__str__())

    """ Used to close the database"""
    def close(self):
        if self.conn:
            self.conn.close()

    """ Incharge to create the database and the table """
    def generate(self):
        # connect to the db without dbname
        try:
            conn = psycopg2.connect("user='%s' password='%s' host='%s'" %
                (self.c['username'], self.c['password'], self.c['host']))
            self.create_db(conn)
            conn.close()
        except psycopg2.OperationalError as e:
            raise MalwasmExceptDbConn(e.__str__())
       
        # reconnect to the db with a dbname
        self.connect()
        self.create_schema()

    def create_db(self, conn):
        """ Create the database, and drop it if already exist """

        # change transaction level to create the database
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        logging.info("Create database %s" % self.c['dbname'])
        try:
            # prepared statement failed on this instruction so old way
            sql = "CREATE DATABASE %s" % self.c['dbname']
            logging.debug("SQL request: %s", sql);
            cur.execute(sql)
        except psycopg2.ProgrammingError as e:
            error_str = psycopg2.errorcodes.lookup(e.pgcode)
            logging.debug("psycopg2.ProgrammingError: %s", error_str)

            if error_str  == "DUPLICATE_DATABASE":
                logging.debug("Database %s already exists", self.c['dbname'])
                self.drop_db(conn)
                self.create_db(conn)
        finally:
            cur.close()

    """ Drop the dbname """
    def drop_db(self, conn):
        try:
            cur = conn.cursor()
            logging.info("Drop the database")
            # prepared statement failed on this instruction so old way
            sql = "DROP DATABASE %s" % self.c['dbname']
            logging.debug("SQL request: %s", sql);
            cur.execute(sql)
        except psycopg2.ProgrammingError as e:
            raise MalwasmExceptDb(e.__str__())
        finally:
            cur.close()

    """ Parse a schema file and execute the queries """
    def create_schema(self):
        # format the file to get one request by line
        file_data = open(MALWASM_DB_SCHEMA, 'r').read()
        file_data = file_data.replace('\n', '')
        file_data = file_data.replace(';', ';\n')
        file_data = file_data.strip('\n') # remove the last \n
        queries = file_data.split('\n')

        logging.info("Create tables from the schema file")
        cur = self.conn.cursor()
        for q in queries:
            try:
                logging.debug("SQL request: %s", q);
                cur.execute(q)
            except psycopg2.ProgrammingError as e:
                error_str = psycopg2.errorcodes.lookup(e.pgcode)
                logging.debug("psycopg2.ProgrammingError: %s", error_str)
                self.conn.rollback()
                cur.close()
                raise MalwasmExceptDb(e.__str__())

        self.conn.commit()
        cur.close()

    """ Insert a new sample with the data into the db """
    def insert(self, data_dir):
        """ @param: exe: path to the binary file
            @param: data_dir: path to the malwpin data
            @return: the sample id """
        sample_id = self.insert_sample(data_dir)
        self.insert_data(sample_id, data_dir)
        self.conn.commit()

    """ Insert the sample into the database 
        if the samples already exist it deletes all 
        old references
    """
    def insert_sample(self, data_dir):
        """ @param: exe: path to the binary file
            @return: the sample id """
        data = open(os.path.join(data_dir, "sample.xml")).read()
        logging.debug("Load the sample XML file")
        doc = xmltodict.parse(data) # Convert XML data into a dictionary

        cur = self.conn.cursor()
        try:
            sample = doc['sample']

            if sample['pin_param']:
                pin_param = sample['pin_param']
            else:
                pin_param = ""

            cur.execute("INSERT INTO sample (filename, md5, insert_at, pin_param) "+\
                    "VALUES (%s, %s, NOW(), %s)",
                (sample['filename'], sample['md5'], pin_param))

            # Warning find a better way to get the last insert element id
            cur.execute("SELECT id FROM sample WHERE md5=%s ORDER BY id DESC", (sample['md5'],))

            sample_id = int(cur.fetchone()[0])
            logging.info("Sample id %d", sample_id)

        except psycopg2.ProgrammingError as e:
            error_str = psycopg2.errorcodes.lookup(e.pgcode)
            logging.debug("psycopg2.ProgrammingError: %s", error_str)
            self.conn.rollback()
            raise MalwasmExceptDb(e.__str__())
        finally:
            cur.close()

        return sample_id


    """ Parse the XML and insert data into the db """
    def insert_data(self, sample_id, data_dir):
        """ @param sample_id: the sample id
            @param data_dir: path to the data directory
        """
        # Read the XML file
        data = open(os.path.join(data_dir, "malwpin.xml")).read()
        logging.debug("Load the malwpin XML file")

        try:
            doc = xmltodict.parse(data + "</info>") # Convert XML data into a dictionary
        except xml.parsers.expat.ExpatError as e:
            logging.debug("XML format error, try to patch the file")
            i = data.rfind('\r\n') # if error it the last line and try again
            data = data[:i]
            try:
                doc = xmltodict.parse(data + "</info>")
            except xml.parsers.expat.ExpatError as e:
                raise MalwasmExceptXml(e)

        info = doc['info'] # Data are in the info fields

        cur = self.conn.cursor()
        try:
            logging.info("Insert instructions data into ins table")

            inss = info.get('ins', list())
            if type(inss) != list:
                inss = [ inss ]

            pbar = ProgressBar(widgets=['Insert instructions, ', ETA(), ' ', Percentage(), Bar()], maxval=len(inss)).start()

            # insert instruction and register information
            for ins in inss:
                reg = ins['reg']

                if ins['name'] is None:
                    ins['name'] = 'unknown:unknown'
                logging.debug('Insert %s', ins['id'])
                cur.execute("INSERT INTO ins " + \
                    "(sample_id, id, thread_id, adr, asm, name, comment)" + \
                    " VALUES (%s, %s, %s, %s, %s, %s, %s)", 
                    (sample_id, ins['id'], ins['thread'], reg['eip'], 
                    ins['asm'], ins['name'], ins['comment']))
                
                cur.execute("INSERT INTO reg "+ \
                    "(sample_id, ins_id, thread_id, eax, ebx, ecx, " + \
                    "edx, edi, esi, ebp, esp, eip, eflags) VALUES " + \
                    "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (sample_id, ins['id'], ins['thread'], reg['eax'], 
                    reg['ebx'], reg['ecx'], reg['edx'], 
                    reg['edi'], reg['esi'], reg['ebp'], 
                    reg['esp'], reg['eip'], reg['eflags']))

                pbar.update(pbar.currval + 1)

            pbar.finish()
            
            logging.info("Insert data dump into dump table")
            
            data = info.get('data', list())
            if type(data) != list:
                data = [ data ]
            
            pbar = ProgressBar(widgets=['Insert data dumps, ', ETA(), ' ', Percentage(), Bar()], maxval=len(data)).start()
            
            # insert data into dump table 
            for d in data:
                filename = os.path.join(data_dir, 
                    "memory", "data_%s_%s_%s.dmp" % (d['id'], d['thread'], d['start']))

                dump = open(filename, 'rb').read()
                cur.execute("INSERT INTO dump " +\
                    "(sample_id, ins_id, thread_id, " +\
                    "adr_start, adr_stop, cur, data) VALUES " +\
                    "(%s, %s, %s, %s, %s, %s, %s)", 
                    (sample_id, d['id'], d['thread'], d['start'], 
                    d['end'], d['cur'], psycopg2.Binary(dump)))
                pbar.update(pbar.currval + 1)

            pbar.finish()
            
        except psycopg2.ProgrammingError as e:
            error_str = psycopg2.errorcodes.lookup(e.pgcode)
            logging.debug("psycopg2.ProgrammingError: %s", error_str)
            self.conn.rollback()
            raise MalwasmExceptDb(e.__str__())
        except KeyboardInterrupt:
            logging.error("Keyboard interrupt")
            self.conn.rollback()
        finally:
            cur.close()


    """ Compute a md5 for a file """
    def file_to_md5(self, filename):
        """ @return: md5 hash of the file """
        file_content = open(filename, "rb").read()
        md5 = hashlib.md5(file_content).hexdigest()
        return md5
