''' helpers.py - common functionality for testing DADB

Copyright (c) 2023-2025 Netherlands Forensic Institute - MIT License
Copyright (c) 2024-2025 mxkrt@lsjam.nl - MIT License
'''

import tempfile
import os
import random
import subprocess

from .._database import Database

MODULE_NAME = 'dadb'
DATADIR = os.path.join('dadb', 'test', 'data')
GENDIR = os.path.join(DATADIR, 'generated')


def correct_path():
    ''' Determines if I'm running in the toplevel package path. '''

    # check if we find the proper subdirs
    files = os.listdir(os.path.curdir)
    assert MODULE_NAME in files, \
        'invoke test from toplevel package directory.'

    # and below it, the DATADIR should exist
    assert os.path.exists(os.path.join(os.path.curdir, DATADIR)) is True, \
        'invoke test from toplevel package directory.'

    # and check the directories underneath the DATADIR
    assert os.path.exists(os.path.join(os.path.curdir, GENDIR)) is True, \
        'invoke test from toplevel package directory.'


def clean_generated():
    ''' Removes the generated testdata '''

    correct_path()
    files = os.listdir(GENDIR)
    for f in files:
        # only remove temporary files.
        if f.startswith('tmp'):
            os.remove(os.path.join(GENDIR, f))
    files = os.listdir(GENDIR)
    if files != ['.keep']:
        raise ValueError('some unmanaged files remain in {:}: {:}'.format(GENDIR, files))


def generate_random_file():
    ''' Generate a random file in GENDIR and calculate sha256 '''

    # make sure we are running in the proper path
    correct_path()

    # generate a temporary file
    tmp = tempfile.NamedTemporaryFile(dir=GENDIR, delete=False)
    tmp.close()
    # fill the temporary file with random data
    blocksize = int(random.random() * 1024 * 1024)
    count =     int(random.random() * 60)
    if count == 0: count = 1
    if blocksize == 0: blocksize = 1024 * 1024
    proc = subprocess.Popen(['dd','if=/dev/urandom','of='+tmp.name,
                     'bs='+ str(blocksize),'count='+ str(count)],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = [l.decode().rstrip() for l in proc.stdout]
    stderr = [l.decode().rstrip() for l in proc.stderr]
    if stdout != []:
        raise ValueError("dd produced output on stdout: {:}".format(' '.join(stdout)))

    proc = subprocess.Popen(['sha256sum',tmp.name],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = [l.decode().rstrip() for l in proc.stdout]
    stderr = [l.decode().rstrip() for l in proc.stderr]
    if stderr != []:
        raise ValueError("sha256sum produced output on stderr: {:}".format(' '.join(stderr)))

    sha256, path = stdout[0].split()
    return sha256, path


def generate_random_files():
    ''' generate multiple random files in GENDIR and calculate their sha256 '''

    # make sure we are running in the proper path
    correct_path()

    # generate up to 50 temporary files
    count = int(random.random() * 50)

    tempfiles = {}
    for i in range(count):
        sha256, path = generate_random_file()
        tempfiles[sha256] = path
    return tempfiles


def generate_testdb():
    ''' Creates a test DADB database '''

    # make sure we are running in the proper path
    correct_path()

    # abuse the tempfile module to generate a random name
    tmp = tempfile.NamedTemporaryFile(dir=GENDIR)
    name = tmp.name
    tmp.close

    db = Database(name+".db")
    db.create()

    return db
