''' _schema.py - database schema and query builders for DADB

Copyright (c) 2023-2025 Netherlands Forensic Institute - MIT License
Copyright (c) 2024-2025 mxkrt@lsjam.nl - MIT License
'''

from collections import namedtuple as _nt

# increment when changing these core tables 
# (consider changing API level as well)
SCHEMAVERSION = 3

# names of the operational tables
ENUMTBLNAME = '_enum_'
MODELTBLNAME = '_model_'
FIELDTBLNAME = '_field_'
MAPTBLNAME = '_maptable_'
PROPTBLNAME = '_proptable_'

# structure for defining a column
#
# name:           column name
# description:    documentation
# coldef:         CREATE TABLE substatement to create the column
col = _nt('col', 'name description coldef')

# structure for defining a table
#
# name:           table name
# description:    documentation
# fields:         a list of col elements as defined above
# tblconstraint:  a table constraint passed verbatim into CREATE TABLE statement
tbl = _nt('table', 'name description fields tblconstraint')


# meta-metadata needed for dadb operations
_reserved_ =  tbl('_reserved_', 'state keeping for reopening database',(
                  col('pkey_', 'name to use for pkey columns', 'TEXT'),
                  col('schemaversion', 'version number of database schema', 'INTEGER NOT NULL'),
                  col('apiversion', 'version number of DADB API', 'INTEGER NOT NULL'),
                  col('prefix_', 'prefix used in all table and field names' , 'TEXT'),
                  col('timeline_blacklist', 'list of modelnames to exclude from timeline', 'TEXT')),
                  None)


# table for enum definitions
_enumtable_ = tbl(ENUMTBLNAME, 'table that points to autogenerated enum tables',(
                  col('id_', 'id of enum in this database', 'INTEGER PRIMARY KEY AUTOINCREMENT'),
                  col('name_', 'original name of the enum', 'TEXT NOT NULL'),
                  col('table_', 'table name for this enum', 'TEXT NOT NULL'),
                  col('source_', 'label for source, i.e. autogenerated', 'TEXT NOT NULL'),
                  col('version_', 'version of the enum definition', 'INTEGER NOT NULL'),
                  col('table_prefix_', 'prefix used in tablename','TEXT NOT NULL')),
                  None)


# table for model definitions
_modeltable_ = tbl(MODELTBLNAME, 'keep track of autogenerated model tables', (
                   col('id_', 'id of model in this database', 'INTEGER PRIMARY KEY AUTOINCREMENT'),
                   col('name_', 'original name of the model', 'TEXT NOT NULL'),
                   col('table_', 'table name for this model', 'TEXT NOT NULL'),
                   col('source_', 'label for source, i.e. autogenerated', 'TEXT NOT NULL'),
                   col('version_', 'version of the model', 'INTEGER NOT NULL'),
                   col('table_prefix_', 'prefix used in tablename', 'TEXT NOT NULL'),
                   col('field_prefix_', 'prefix used in fieldnames', 'TEXT NOT NULL'),
                   col('explicit_dedup_', 'deduplicate explicitly inserted items', 'INTEGER'),
                   col('implicit_dedup_', 'deduplicate implicitly inserted items', 'INTEGER'),
                   col('fail_on_dup_', 'whether to fail on duplicate item insert', 'INTEGER')),
                   None)


# table for field definitions
_fieldtable_ = tbl(FIELDTBLNAME, 'fielddescriptors for model fields', (
                   col('id_', 'id of fielddescriptor', 'INTEGER PRIMARY KEY AUTOINCREMENT'),
                   col('modelid_', 'pointer to model entry', 'INTEGER NOT NULL'),
                   col('name_', 'original name of field', 'TEXT NOT NULL'),
                   col('colname_', 'name of column in model table', 'TEXT'),
                   col('datatype_', 'description of datatype', 'TEXT'),
                   col('nullable_', 'whether NULL values are allowed', 'INTEGER'),
                   col('multiple_', 'whether field contains list of values', 'INTEGER'),
                   col('submodel_', 'field contains pointer to other model', 'INTEGER'),
                   col('enum_', 'field contains pointer to enum', 'INTEGER'),
                   col('preview_', 'field is included in previews', 'INTEGER')),
                   'UNIQUE (modelid_, name_)')


# table for mapping table definitions
_maptable_ = tbl(MAPTBLNAME, 'descriptor for mapped fields', (
                 col('field_', 'points to model_field', 'INTEGER'),
                 col('maptable_', 'name of m:n mapping table', 'TEXT UNIQUE'),
                 col('enum_', 'points to enum if field contains enums', 'INTEGER'),
                 col('model_', 'points to model if modelitems in field', 'INTEGER')),
                 'PRIMARY KEY (field_, maptable_)')

# table for property table definitions
_propertytable_ = tbl(PROPTBLNAME, 'descriptor for property fields', (
                      col('field_', 'points to field', 'INTEGER'),
                      col('datatype_', 'description of datatype', 'TEXT'),
                      col('proptable_', 'name of property table', 'TEXT')),
                      'PRIMARY KEY (field_, proptable_)')

# list of the 5 operational tables
_operational_tables_ = [_enumtable_, _modeltable_, _fieldtable_, _maptable_, _propertytable_]


# tables related to a data object
_data_ = tbl('data', 'metadata on a single data object', (
             col('id', 'id of data object', 'INTEGER PRIMARY KEY AUTOINCREMENT'),
             col('md5', 'md5 hash of data-object', 'TEXT NOT NULL'),
             col('sha1', 'sha1 hash of data-object', 'TEXT NOT NULL'),
             col('sha256', 'sha256 hash of data-object', 'TEXT NOT NULL'),
             col('size', 'total size of data-object', 'INTEGER NOT NULL'),
             col('stored', '1 if data is in database, 0 otherwise', 'INTEGER NOT NULL')),
             None)

# table related to a single block of data
_block_ = tbl('block', 'stores single blocks of data', (
              col('id', 'id of this block', 'INTEGER PRIMARY KEY AUTOINCREMENT'),
              col('sha1', 'sha1 hash of block', 'TEXT NOT NULL'),
              col('size', 'size of block', 'INTEGER NOT NULL'),
              col('data', 'the actual data in this block', 'BLOB NOT NULL')),
              None)

# table mapping blocks to data objects
_blockmap_ = tbl('blockmap', 'maps blocks to data objects', (
                 col('dataid', 'id of data object', 'INTEGER NOT NULL'),
                 col('blkid', 'id of block object', 'INTEGER NOT NULL'),
                 col('offset', 'offset of block in data object', 'INTEGER NOT NULL')),
                 'PRIMARY KEY (dataid, offset)')

# list of the 3 data tables
_data_tables_ = [_data_, _block_, _blockmap_]


def validname(name, prefix='x'):
    ''' converts given string to a prefixed SQLite name '''

    # NOTE: only two special characters are checked, 
    #       we probably need something more robust
    name = name.replace('.','_')
    name = name.replace('+','_')

    return '%s%s' % (prefix, name, )


def enum_tabledef(prefix, tblname):
    ''' generate the table definition for an enum '''

    _val = prefix+'val'
    _name = prefix+'name'
    return tbl(tblname, 'auto-generated enum table', (
               col(_val, 'enum_value', 'INTEGER PRIMARY KEY NOT NULL'),
               col(_name, 'enum_string', 'TEXT NOT NULL')),
              'UNIQUE ({:s}, {:s})'.format(_val, _name))


def timeline_fields(db, excluded=None):
    ''' determine which fields to include in timeline '''

    # select the fields with a Datetime or Date type
    # (expand to list to prevent issues with nested queries)
    dtfields = list(db.select('_fieldinfo_', where={'datatype_':'Datetime'},
                    cursor=db.dbcur))
    dfields = list(db.select('_fieldinfo_', where={'datatype_':'Date'},
                   cursor=db.dbcur))

    if excluded is not None:
        if isinstance(excluded, list):
            for mname in excluded:
                if mname not in db.models:
                    raise ValueError('timeline exclusion list contains invalid modelname')
            dtfields = [f for f in dtfields if f.modelname_ not in excluded]
            dfields = [f for f in dfields if f.modelname_ not in excluded]
        else:
            raise ValueError('expected list of modelnames to exclude from timeline')
    return dtfields + dfields


def create_timeline_view(db, excluded=None):
    ''' creates a timeline view in the given DADB database '''

    # make sure it is all done, or nothing at all
    started_transaction = db.begin_transaction()

    q = 'DROP VIEW IF EXISTS {:s}Timeline_'.format(db.prefix)
    db.dbcur.execute(q)

    # select the fields with a Datetime or Date type
    # (expand to list to prevent issues with nested queries)
    dtfields = list(db.select('_fieldinfo_', where={'datatype_':'Datetime'},
                    cursor=db.dbcur))
    dfields = list(db.select('_fieldinfo_', where={'datatype_':'Date'},
                   cursor=db.dbcur))

    if excluded is not None:
        if isinstance(excluded, list):
            for mname in excluded:
                if mname not in db.models:
                    raise ValueError('timeline exclusion list contains invalid modelname')
            dtfields = [f for f in dtfields if f.modelname_ not in excluded]
            dfields = [f for f in dfields if f.modelname_ not in excluded]
        else:
            raise ValueError('expected list of modelnames to exclude from timeline')

    # create the model part of the query
    subdt = [_modeltimeline_subquery(db, fd) for fd in dtfields]
    subd = [_modeltimeline_subquery(db, fd) for fd in dfields]
    # NOTE: this will be empty if there is no modeldata or if there are no 
    # Datetime/Date fields in any of the models
    allfields = subdt + subd

    if len(allfields) == 0:
        if started_transaction is True:
            db.dbcur.execute('COMMIT')
        return

    # build and execute the complete query
    # the name of the timeline table should also be prefixed
    q = "CREATE VIEW {:s}Timeline_ AS {:s} ORDER BY timestamp_"
    megaquery = q.format(db.prefix, '\n\nUNION\n\n'.join(allfields))
    db.dbcur.execute(megaquery)

    # end transaction if we started it
    if started_transaction is True:
        db.dbcur.execute('COMMIT')


def _modeltimeline_subquery(db, fd):
    ''' subqueries for getting timeinfo from models '''

    # the base query for timeline view creation of a single datetime field
    q = "SELECT {:s} AS timestamp_,\n '{:s}' AS timestampfield_,\n " +\
            "'{:s}' AS table_\n, {:s}{:s}\n, {:s} AS preview_\n " +\
        "FROM {:s} \nWHERE {:s} is not NULL"

    # the columns to use in the timeline view
    columns = db.select('_fieldinfo_',
                        where={'modeltable_': getattr(fd, 'modeltable_')},
                        cursor=db.dbcur)

    # skip binary columns and columns with no values
    columns = filter(lambda c: getattr(c, 'datatype_') not in ['Bytes', None, ''], columns)
    # and columns that should be hidden from previews
    columns = filter(lambda c: bool(getattr(c, 'preview_')) is True, columns)
    # and place the columnnames in a list
    colnames = [(getattr(cc, 'fieldname_'), getattr(cc, 'columnname_')) for cc in columns]

    if len(colnames) == 0:
        preview = "''"
    else:
        # add CAST to String
        colnames = ["'{:s}:' || COALESCE(CAST({:s} AS TEXT),'')\n".format(c[0],c[1]) for c in colnames]
        # create the preview query
        preview = " || '|' || ".join(colnames)

    query = q.format(getattr(fd, 'columnname_'),
                     getattr(fd, 'columnname_'),
                     getattr(fd, 'modeltable_'),
                     db.prefix, db.pkey, preview,
                     getattr(fd, 'modeltable_'),
                     getattr(fd, 'columnname_'))
    return query


def create_fieldinfo_view(db):
    ''' creates a view with properties for each field in the modeltables.

    It is best to call this function from within a transaction, but this is
    not enforced.  '''

    db.dbcur.execute('DROP VIEW IF EXISTS _fieldinfo_')
    d = '''
        CREATE VIEW _fieldinfo_ as
        SELECT '''+MODELTBLNAME+'''.name_ as modelname_,
               '''+MODELTBLNAME+'''.table_ as modeltable_,
               '''+FIELDTBLNAME+'''.name_ as fieldname_,
               '''+FIELDTBLNAME+'''.colname_ columnname_,
               '''+FIELDTBLNAME+'''.datatype_ as datatype_,
               '''+FIELDTBLNAME+'''.preview_ as preview_,
               (SELECT CASE
                  WHEN '''+FIELDTBLNAME+'''.submodel_ != ''
                     THEN (SELECT table_ FROM '''+MODELTBLNAME+ \
                           ''' WHERE id_ == '''+FIELDTBLNAME+'''.submodel_)
                  WHEN '''+FIELDTBLNAME+'''.enum_ != ''
                     THEN (SELECT table_ FROM '''+ENUMTBLNAME+ \
                           ''' WHERE id_ == '''+FIELDTBLNAME+'''.enum_)
               END) as points_to_,
               (SELECT CASE
                  WHEN '''+MAPTBLNAME+'''.enum_ != ''
                     THEN (SELECT table_ FROM '''+ENUMTBLNAME+ \
                           ''' WHERE id_ == '''+MAPTBLNAME+'''.enum_)
                  WHEN '''+MAPTBLNAME+'''.model_ != ''
                     THEN (SELECT table_ FROM '''+MODELTBLNAME+ \
                           ''' WHERE id_ == '''+MAPTBLNAME+'''.model_)
               END) as maps_to_,
               '''+MAPTBLNAME+'''.maptable_ as mapping_table_,
               '''+PROPTBLNAME+'''.proptable_ as property_table_,
               '''+PROPTBLNAME+'''.datatype_ as property_datatype_
        FROM '''+FIELDTBLNAME+ \
                ''' LEFT JOIN '''+MODELTBLNAME+ \
                ''' on '''+FIELDTBLNAME+'''.modelid_ == '''+MODELTBLNAME+'''.id_
        LEFT JOIN '''+MAPTBLNAME+''' on '''+FIELDTBLNAME+ \
                '''.id_ == '''+MAPTBLNAME+'''.field_
        LEFT JOIN '''+PROPTBLNAME+''' on '''+ \
                FIELDTBLNAME+'''.id_ == '''+PROPTBLNAME+'''.field_;
        '''
    db.dbcur.execute(d)
