''' test_database.py - tests for the Database class in DADB

Copyright (c) 2023-2025 Netherlands Forensic Institute - MIT License
Copyright (c) 2024-2025 mxkrt@lsjam.nl - MIT License
'''

from io import BytesIO as _BytesIO

from . import helpers as _helpers
from .._model_definition import field_definition as _field_def
from .._model_definition import model_definition as _model_def
from .._database import Database as _Database
from .._exceptions import NoSuchDataObjectError as _NoSuchDataObjectError


def test_datatabase_object():
    ''' test the Database object '''

    # check if we are running from the correct path
    _helpers.correct_path()

    # generate a test database
    database = _helpers.generate_testdb()

    name = database.dbname

    database.close()
    database = _Database(name)
    database.load()
    database.reload()

    _basic_properties(database)
    _transactions(database)

    # cleanup generated files
    _helpers.clean_generated()


def _basic_properties(database):
    ''' test the basic properties of the database '''

    if database.pkey != 'id':
        raise ValueError('expected pkey id')

    if database.prefix != 'x':
        raise ValueError('expected prefix x')

    expected_tables = ['_reserved_', '_enum_', '_model_', '_field_',
                       '_maptable_', '_proptable_', 'xdata', 'xblock',
                       'xblockmap']

    if list(database.tables.keys()) != expected_tables:
        raise ValueError('unexpected tables in test database')

    if database.models != {}:
        raise ValueError('expected empty models dict')

    if database.enums != {}:
        raise ValueError('expected empty enums dict')

    expected_datatypes = ['Datetime', 'Date', 'Integer', 'String', 'Bytes',
                          'Bool', 'TimeDelta', 'Float', 'NULL', 'Data']

    if list(database.datatypes.keys()) != expected_datatypes:
        raise ValueError('error in datatypes')


def _transactions(database):
    ''' test transactions '''

    # start a transaction
    started_transaction = database.begin_transaction()
    if started_transaction is False:
        raise ValueError('expected started_transaction is True')

    # now starting a transaction again should be rejected gracefully
    started_transaction1 = database.begin_transaction()
    if started_transaction1 is True:
        raise ValueError('expected started_transaction is False')

    # now insert some data into the database
    bytes_ = b'\x00\x01\x02\x03\x04\x05\x06'
    bytesio_ = _BytesIO(bytes_)
    dataid = database.insert_data(bytesio_)
    # and read it back
    read_bytes = database.get_data(dataid).read()
    if read_bytes != bytes_:
        raise ValueError('error in reading back bytes')

    # now rollback the transaction
    rolled_back = database.rollback_transaction()

    if rolled_back is False:
        raise ValueError('expected rollback to succeed')

    # and attempt to get the bytes with the same rowid again
    try:
        data_obj = database.get_data(dataid)
        raise ValueError('expected data object to be unavailable')
    except _NoSuchDataObjectError:
        pass

    # now attempt to rollback again
    rolled_back = database.rollback_transaction()

    if rolled_back is True:
        raise ValueError('expected rollback to fail')

    # start a transaction
    started_transaction = database.begin_transaction()
    if started_transaction is False:
        raise ValueError('expected started_transaction is True')

    # now insert some data into the database
    bytes_ = b'\x00\x01\x02\x03\x04\x05\x06'
    bytesio_ = _BytesIO(bytes_)
    dataid = database.insert_data(bytesio_)
    # and read it back
    read_bytes = database.get_data(dataid).read()
    if read_bytes != bytes_:
        raise ValueError('error in reading back bytes')

    # commit
    database.end_transaction()

    # and read it back
    read_bytes = database.get_data(dataid).read()
    if read_bytes != bytes_:
        raise ValueError('error in reading back bytes')
