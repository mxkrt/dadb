''' test_data.py - tests for the Data class in DADB

Copyright (c) 2023-2025 Netherlands Forensic Institute - MIT License
Copyright (c) 2024-2025 mxkrt@lsjam.nl - MIT License
'''

import subprocess
from . import helpers


def insert_data(database, tempfiles):
    ''' insert the data objects from the tempfiles into the database '''

    # keep track of the mapping of object_ids of the Data objects to the
    # filenames of the originating files
    data_objects = {}

    for sha256, name in tempfiles.items():
        with open(name, 'rb') as f:
            oid = database.insert_data(f)
            data_objects[oid] = (sha256, name)

    return data_objects


def check_stored_hashes(database, objects):
    ''' for each file check if the stored sha256 matches the original sha256
    '''

    for id_, (sha256, path) in objects.items():
        data_object = database.get_data(id_)
        if data_object.sha256 != sha256:
            raise ValueError("sha256 mismatch for {:}".format(path))


def check_reading(database, objects):
    ''' check data by reading the data back from the database and writing to
    file system and comparing with input data '''

    for id_, (sha256, path) in objects.items():
        data_object = database.get_data(id_)
        outname = path + ".out"
        open(outname, 'wb').write(data_object.read())
        proc = subprocess.Popen(['cmp',path, outname],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = [l.decode().rstrip() for l in proc.stdout]
        stderr = [l.decode().rstrip() for l in proc.stderr]
        if stdout != []:
            raise ValueError(' '.join(stdout))


def check_size(database, objects):
    ''' check data by reading the data back from the database and writing to
    filesystem and comparing with input data '''

    for id_, (sha256, path) in objects.items():
        data_object = database.get_data(id_)
        # call the check_length function
        data_object._check_length()
        proc = subprocess.Popen(['stat','-c', '%s', path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = [l.decode().rstrip() for l in proc.stdout]
        if len(stdout) != 1:
            raise ValueError("something wrong in stat output")
        size = int(stdout[0])
        if size != data_object.length:
            raise ValueError("incorrect size for data object in database")


def test_data_object():
    ''' test the Data object '''

    # check if we are running from the correct path
    helpers.correct_path()

    # clean the tempdir
    helpers.clean_generated()

    # generate temporary files
    tempfiles = helpers.generate_random_files()

    # generate a test database
    database = helpers.generate_testdb()

    # insert the data into the test database
    objects = insert_data(database, tempfiles)

    # check the stored hashes for the inserted binary data
    check_stored_hashes(database, objects)

    # check reading back the data objects
    check_reading(database, objects)

    # check size of data objects
    check_size(database, objects)

    # cleanup generated files
    helpers.clean_generated()
