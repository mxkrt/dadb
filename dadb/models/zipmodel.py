''' zipmodel.py - model to extract zipfiles

Copyright (c) 2023-2025 Netherlands Forensic Institute - MIT License
Copyright (c) 2024-2025 mxkrt@lsjam.nl - MIT License
'''

import zipfile as _zipfile
import os as _os
import re as _re
import fnmatch as _fnmatch
from datetime import datetime as _datetime
from pytz import utc as _utc
from struct import unpack as _unpack

from .. import model_definition as _model_def
from .. import field_definition as _field_def
from .. import progresswrapper as _progresswrapper
from .. import exceptions as _exceptions

from . import filemodel as _fmodel
from . import filesetmodel as _fsetmodel
from . import libmagicmodel as _libmagicmodel
from . import fileparentmodel as _fparentmodel


##########
# MODELS #
##########

# changelog:
# 1 - initial model version
# 2 - added support for partially extracting files
# 3 - store the used whitelist for partial files

MODELNAME='zipfile'
MODELDESCRIPTION='zipfile model for DADB'
MODELVERSION = 3


modeldef = _model_def(MODELNAME,
                      [_field_def('file', _fmodel.modeldef, nullable=False),
                       _field_def('contents', _fsetmodel.modeldef),
                       _field_def('error', str),
                       _field_def('partial', bool),
                       _field_def('whitelist', str)],
                      MODELDESCRIPTION, MODELVERSION,
                      implicit_dedup=True, fail_on_dup=True)


# files that can be extracted using zipmodel
ZIP_MIMES = ['application/zip', 'application/java-archive']


#######
# API #
#######


def register_with_db(db):
    ''' register the model and its dependencies to the database '''

    _fmodel.register_with_db(db)
    _fsetmodel.register_with_db(db)
    _fparentmodel.register_with_db(db)
    _libmagicmodel.register_with_db(db)
    db.register_model(modeldef)


def insert_local_file(db, filename, whitelist=None, progress=False):
    ''' insert a local file directly as zip-file, return (fileid, zipid)

    When using this function, the zipfile is extracted directly without
    storing the intermediate file-blocks of the actual zip file (only the
    meta-data of the outer zipfile is stored). In addition, all extracted
    file data is stored with metadata.

    When the whitelist argument is given only the files matching the given
    globbing pathname wildcard patterns are extracted and stored in the
    database. The supported wildcard characters are '?' and '*'.
    '''

    # check if the model is already registered
    db.check_registered(MODELNAME)

    # make sure everything happens in a single transaction
    started_transaction = db.begin_transaction()

    try:
        if progress is True:
            print('    unzip: {:}'.format(filename))
            print('    - hashing and inserting metadata...', end='', flush=True)
        file_id, mmapped = _fmodel.insert(db, filename, do_mmap=True)
        if progress is True:
            print('done', flush=True)
        rowid = insert(db, file_id, mmapped, whitelist, progress)
    except:
        if started_transaction is True:
            db.rollback_transaction()
        raise

    if started_transaction is True:
        db.end_transaction()

    return file_id, rowid


def insert(db, fileid, fileobj=None, whitelist=None, progress=False):
    ''' extracts the given file if it is a zipfile and not extracted yet '''

    # check if the model is already registered
    db.check_registered(MODELNAME)

    # check if the file was already processed
    existing = _entry_by_fileid(db, fileid)
    if existing is not None:
        return existing

    # make sure everything happens in a single transaction
    started_transaction = db.begin_transaction()

    try:
        rowid = _insert(db, fileid, fileobj, whitelist, progress)
    except:
        if started_transaction is True:
            db.rollback_transaction()
        raise

    if started_transaction is True:
        db.end_transaction()

    return rowid


def update(db, whitelist=None, progress=False, maxrounds=5):
    ''' extract unprocessed zipfiles into new file objects.

    Maxrounds limits the max number of extraction rounds '''

    db.check_registered(MODELNAME)

    round_ = 0
    while round_ < maxrounds:
        # run libmagic over the file model items
        # (libmagic manages it's own transaction)
        _libmagicmodel.update(db, progress)

        # keep track of processed files
        c = 0

        # perform each round in a transaction, as to prevent rolling
        # back all rounds, when error occurs in last round
        db.begin_transaction()

        # perform a single unzip round
        try:
            c += _unzipround(db, whitelist, progress)
            db.end_transaction()
        except:
            db.rollback_transaction()
            raise

        if c == 0:
            # No files extracted this round, no need to continue
            break

        round_+= 1


def get(db, object_id):
    ''' returns the modelitem by its object_id '''

    try:
        return db.modelitem(MODELNAME, object_id)
    except _exceptions.NoSuchModelItemError:
        return None


def get_by_fileid(db, fileid, with_pkey=False):
    ''' return model item for file with given fileid '''

    id_ = _entry_by_fileid(db, fileid)
    if id_ is not None:
        item = db.modelitem(MODELNAME, id_)
        if with_pkey is True: return id_, item
        else: return item
    return None


def items(db, with_pkey=False):
    ''' yield modelitems '''

    return db.modelitems(MODELNAME, with_pkey)


def extracted_files(db, only_pkey=False):
    ''' generate files that where successfully extracted without errors '''

    if only_pkey is True:
        for fid in _extracted_files(db):
            yield fid
    else:
        for fid in _extracted_files(db):
            yield _fmodel.get(db, fid)


####################
# helper functions #
####################


# global variables to hold some of the queries used
_BY_FILEID_QUERY = None


def _insert(db, fileid, fobj=None, whitelist=None, progress=False, sep='/', icall=False):
    ''' attempt to insert given file as zipmodel item '''

    if icall is True:
        do_checks, do_magic = False, False
    else:
        do_checks, do_magic = True, True

    if whitelist == None:
        partial = False
        whitelist_field = None
    else:
        partial = True
        whitelist_field = repr(whitelist)

    try:
        if fobj is None:
            zf = _open_zip_from_db(db, fileid, do_checks, do_magic)
        else:
            zf = _open_zip_from_fileobj(fobj)
        if zf is None:
            return None
        # extract the zip and log an error if it fails
        rowids = _unzip(db, zf, fileid, sep, whitelist, progress)
    except Exception as e:
        # create modelitem with the error
        m = db.make_modelitem(MODELNAME, file=fileid, contents=None,
                              error=repr(e), partial=partial,
                              whitelist=whitelist_field)
        rowid = db.insert_modelitem(m)
        return rowid

    # if we get here the file was extracted without error, so we can
    # add the fileset and the fileparent relations and the zipmodel item
    db.disable_duplicate_checking(_fparentmodel.MODELNAME)
    try:
        if len(rowids) == 0:
            fset = None
        else:
            label = 'extracted from file {:} by {:}'.format(fileid, MODELNAME)
            fset = _fsetmodel.insert(db, label, tuple(rowids))
            _fparentmodel.insert_files(db, rowids, fileid, progress)
        m = db.make_modelitem(MODELNAME, file=fileid, contents=fset,
                              error=None, partial=partial,
                              whitelist=whitelist_field)
        rowid = db.insert_modelitem(m)
    finally:
        db.enable_duplicate_checking(_fparentmodel.MODELNAME)

    return rowid


def _open_zip_from_db(db, fileid, do_checks=True, do_magic=True):
    ''' return given file as ZipFile object '''

    # get the file with the given fileid
    f = _fmodel.get(db, fileid)

    # check if the file exists and contains any data
    if do_checks is True:
        if f is None:
            return
        if f.ftype.value != _fmodel.Filetype.regular_file.value:
            return None
        if f.size == 0:
            return None
        if f.data is None:
            return None
        if f.data.stored is False:
            return None

    # check if this is a ZIP type
    if do_magic is True:
        filemagic = _libmagicmodel.get_by_fileid(db, fileid)
        if filemagic is None:
            _libmagicmodel.insert(db, fileid)
            filemagic = _libmagicmodel.get_by_fileid(db, fileid)
        if filemagic.mimetype not in ZIP_MIMES:
            return None

    # make sure we start at the beginning
    if f.data.seekable() is True:
        f.data.seek(0)

    # try if we can open the file as a zipfile
    # (will raise BadZipFile error upon failure)
    return _zipfile.ZipFile(f.data)


def _open_zip_from_fileobj(fileobj):
    ''' return given file as ZipFile object '''

    # make sure we start at the beginning
    fileobj.seek(0)

    # try if we can open the file as a zipfile
    # (will raise BadZipFile error upon failure)
    return _zipfile.ZipFile(fileobj)


def _unzip(db, zf, fileid, sep, whitelist, progress):
    ''' extract the given ZipFile object '''

    # extract the file data and store as Data objects in the database
    # while collecting the metadata in a list
    filelist = []
    for f in _extract_files(db, zf, sep, whitelist, progress):
        filelist.append(f)

    # we have seen zipfiles where intermediate paths have no explicit zip
    # member, we need to generate these ourselves to maintain a proper file
    # hierarchy
    missing_dirs = _missing_directories(db, filelist, fileid)

    # before inserting the modelitems, disable duplicate checking, since
    # processed zipfiles are not processed twice, and because we add specific
    # user tags to each extracted file to make them unique.
    # NOTE: this might lead to duplicates if the file itself contains exact
    # duplicates, but this should normally not occur.
    db.disable_duplicate_checking(_fmodel.MODELNAME)

    # Iterate over the members and insert the file modelitems
    rowids = []

    if progress is True:
        filelist = _progresswrapper(filelist, '{:20s}'.format('    insert files'))

    # create the file modelitems and insert into the database
    try:
        for f in filelist:
            m = _make_modelitem(db, f, fileid)
            rowid = db.insert_modelitem(m)
            rowids.append(rowid)

        for m in missing_dirs:
            rowid = db.insert_modelitem(m)
            rowids.append(rowid)

    finally:
        # enable duplicate checking again
        db.enable_duplicate_checking(_fmodel.MODELNAME)

    return rowids


def _extract_files(db, zf, sep, whitelist, progress):
    ''' extract file data and metadata from given zipfile object

    Note: in this function the data for each file is extracted and inserted
    into the database. The id of the corresponding Data object is returned
    as part of the metadata associated with the ZipInfo object.
    '''

    # keep track of files to extract in case of a whitelist
    to_extract = []

    if whitelist != None:
        # convert whitelist with file globbing chars to regular expressions
        whitelist = [_fnmatch.translate(p) for p in whitelist]
        whitelist = [_re.compile(r) for r in whitelist]
        # if we have a whitelist, we want to include the metadata for the
        # directories that contain the files of the whitelisted files as well,
        # so iterate over the infolist to collect the files to extract so
        # we can match directories when iterating the second time
        infolist = zf.infolist()
        for zinfo in infolist:
            for regex in whitelist:
                if regex.match(zinfo.filename):
                    to_extract.append(zinfo.filename)

    # the list of ZipInfo elements
    infolist = zf.infolist()

    if progress is True:
        infolist = _progresswrapper(infolist, '{:20s}'.format('    extracting'))

    for zinfo in infolist:

        if zinfo.filename != zinfo.orig_filename:
            raise ValueError('expected filename and orig_filename to be equal')

        # if we have any files to extract (only when using whitelist)
        # check if the current entry may be the file itself or a directory
        # leading up to the file, which we also want to extract, mainly to
        # preserve the metadata associated with the directory
        if len(to_extract) != 0:
            match = False
            for fname in to_extract:
                match = False
                if zinfo.filename == fname:
                    # this is a file that matches the whitelist
                    match = True
                    break
                elif zinfo.is_dir() is True:
                    if fname.startswith(zinfo.filename):
                        # this is a directory on the path to a file in whitelist
                        match = True
                        break
            if match == False:
                # skip this zinfo object
                continue

        is_dir = zinfo.is_dir()
        data_id = None
        password = False
        if not is_dir:
            try:
                data = zf.open(zinfo.filename)
                data_id = db.insert_data(data)
            except RuntimeError as e:
                if "password required" in e.args[0]:
                    password = True
                else:
                    raise

        # Some ZIP files have absolute paths (i.e. starting with '/').
        # The unzip command strips the forward slash to prevent unpacking
        # over the root filesystem. We need to do the same to prevent our
        # file-hierarchy to be messed up. We also remove trailing path
        # separators for directories
        path = zinfo.filename.lstrip(sep).rstrip(sep)

        # parse additional metadata from the extra field
        extra = None
        if len(zinfo.extra) > 0:
            try:
                extra = _parse_extra(zinfo.extra)
            except:
                # ignore the extra field if a parsing error ocurred
                pass

        # yield the metadata for the current zip entry
        yield (path, zinfo.file_size, zinfo.date_time,
               zinfo.external_attr, zinfo.internal_attr,
               extra, is_dir, data_id, password)

    return


def _make_modelitem(db, values, fileid):
    ''' convert the tuples yielded by _extract_files to modelitems '''

    # determine filename
    fname = _os.path.basename(values[0])

    # determine filetype
    if values[6] is True:
        ftype = _fmodel.Filetype.directory
    else:
        ftype = _fmodel.Filetype.regular_file

    # extract some info from the extra properties
    if values[5] is not None:
        mtime, atime, ctime, btime, uid, gid, inode, device = values[5]
    else:
        mtime, atime, ctime, btime, uid, gid, inode, device = (None,) * 8

    # if mtime is not in extra properties, use the basic naive mtime
    if mtime is None:
        try:
            mtime = _datetime(*values[2])
        except ValueError:
            pass

    # add a user_tag, to make each file unique when duplicates exist in
    # different zip files
    if values[8] is True:
        user_tag = 'could not extract from zipfile {:d}; password required'.format(fileid)
    else:
        user_tag = 'extracted from file {:d} by zipmodel'.format(fileid)

    # make sure the data object is the previously inserted dadb.Data object
    data_obj = db.get_data(values[7])

    # create the modelitem
    m = db.make_modelitem(_fmodel.MODELNAME, name=fname, path=values[0],
                          size=values[1], ftype=ftype, mtime=mtime,
                          atime=atime, ctime=ctime, btime=btime,
                          inode=inode, device=device, uid=uid, gid=gid,
                          deleted=_fmodel.Deleted.intact,
                          data=data_obj, user_tag=user_tag)

    return m


def _parse_extra(data):
    ''' parse a subset of the extra info stored in some zip files '''

    # default values
    mtime, atime, ctime, btime = None, None, None, None
    uid, gid, inode, device = None, None, None, None
    swap_timestamps = False
    extra_time = None

    # scan over the data in order to find extra field magics
    pos = 0
    maxpos = len(data)-4

    while pos < maxpos:
        # parse the header
        magic, size = _unpack('<HH', data[pos:pos+4])
        # carve out the remaining data for the extra block
        field = data[pos+4:pos+4+size]
        # and update our read position
        pos+=4+size

        if magic == 0x5455:  # UT - extended timestamps
            # the spec (https://libzip.org/specifications/extrafld.txt) defines
            # the order of timestamps as: Modification Time, Access Time and
            # Creation Time.  This was confirmed by looking at the source of
            # zip version 3.0.  However some formats have an extra timestamp,
            # in which case the fourth bit is also set.
            flags = int(field[0])
            offset = 1
            # NOTE: added a boundary check because we have seen
            #       zip files where more than 1 flag was set, but
            #       only a single timestamp was stored
            if flags&1 and offset+4 <= size:
                mtime = _unpack('<I', field[offset:offset+4])[0]
                mtime = _datetime.fromtimestamp(mtime, _utc)
                offset += 4
            if flags&2 and offset+4 <= size:
                atime = _unpack('<I', field[offset:offset+4])[0]
                atime = _datetime.fromtimestamp(atime, _utc)
                offset += 4
            if flags&4 and offset+4 <= size:
                btime = _unpack('<I', field[offset:offset+4])[0]
                btime = _datetime.fromtimestamp(btime, _utc)
                offset += 4
            if flags&8 and offset+4 <= size:
                # assume that extra_time is the metadata change time (ctime)
                ctime = _unpack('<I', field[offset:offset+4])[0]
                ctime = _datetime.fromtimestamp(ctime, _utc)
                offset += 4

        elif magic == 0x4e49:   # IN
            inode, device = _unpack("<QI",field)

        elif magic == 0x5855:  # UX
            if size == 8:
                atime, mtime = _unpack("<LL", field)
                atime = _datetime.fromtimestamp(atime, _utc)
                mtime = _datetime.fromtimestamp(mtime, _utc)
            elif size == 12:
                atime, mtime, uid, gid = _unpack("<LLHH", field)
                atime = _datetime.fromtimestamp(atime, _utc)
                mtime = _datetime.fromtimestamp(mtime, _utc)
            else:
                # this should not happen, ignore entry
                pass

        elif magic == 0x7875:  # ux
            version, uidsize = _unpack("<BB", field[0:2])
            # for now ignore other uid/gid sizes
            if uidsize == 4:
                uid, gidsize = _unpack("<IB", field[2:7])
                if uidsize == 4:
                    gid = _unpack("<I", field[7:11])[0]

        elif magic == 0x4b47:
            # observed in some zip files, not 100% sure
            swap_timestamps = True
            field0 = field[0]
            if field0 != 1:
                raise ValueError("Assumption broken: only observed value 1 here")

        else:
            # ignore other blocks silently. Note that we may miss some
            # interesting properties of extracted files, so when debugging /
            # developing consider uncommenting this error
            # raise ValueError("unsupported extra block encountered: {:}".format(magic))
            pass

    if swap_timestamps is True:
        # In this case, ctime and btime seem to be swapped
        raise ValueError("This needs more testing.")
        swap = ctime
        ctime = btime
        btime = swap

    return (mtime, atime, ctime, btime, uid, gid, inode, device)


def _path_with_parents(path):
    ''' yield all parent paths for given path '''

    head, tail = _os.path.split(path)
    while head != '':
        yield head
        head, tail = _os.path.split(head)
    return


def _missing_directories(db, filelist, fileid):
    ''' return list of missing directories in the zip hierarchy '''

    # intermediate directories do not always have a separate entry in
    # the zip file, so in order to create a valid file hierarchy we may
    # need to create intermediate directories ourselves. For this we
    # need to collect all sub-paths that are part of the stored zip entries
    all_dir_paths = set()
    present_dirs = set()
    for f in filelist:
        if f[6] is True:
            # this is a directory
            all_dir_paths.add(f[0])
            present_dirs.add(f[0])
        # add all path parents
        for p in _path_with_parents(f[0]):
            all_dir_paths.add(p)

    # return a set with the missing directory paths
    missing_dirs = all_dir_paths - present_dirs

    if len(missing_dirs) == 0:
        return

    # create modelitems for the missing directories
    user_tag = 'generated intermediate directory as part of extraction of file {:d}'
    user_tag = user_tag.format(fileid)

    for d in missing_dirs:
        name = _os.path.basename(d)
        m = db.make_modelitem(_fmodel.MODELNAME, name=name, path=d, size=0,
                              ftype=_fmodel.Filetype.directory,
                              user_tag=user_tag, deleted=_fmodel.Deleted.intact)
        yield m


def _entry_by_fileid(db, fileid):
    ''' returns rowid of zipmodel item by fileid '''

    # prevent building the query every function call
    global _BY_FILEID_QUERY

    if _BY_FILEID_QUERY is None:
        # get field and table names
        mtbl = db.get_tblname(MODELNAME)
        mfid = db.get_colname(MODELNAME, 'file')
        mkey = db.get_colname(MODELNAME)
        _BY_FILEID_QUERY='SELECT {:s} FROM {:s} WHERE {:s} == ?'.format(mkey, mtbl, mfid)

    results = list(db.dbcon.cursor().execute(_BY_FILEID_QUERY, (fileid,)))
    if len(results) == 0:
        return None
    elif len(results) == 1:
        return results[0][0]
    raise RuntimeError('corrupt database, more than one entry in table')


def _extracted_files(db):
    ''' generates file_ids for files that where extracted without error '''

    # get the names for the involved table and columns
    table = db.get_tblname(MODELNAME)
    fileid = db.get_colname(MODELNAME, 'file')
    error = db.get_colname(MODELNAME, 'error')
    contents = db.get_colname(MODELNAME, 'contents')

    # select zipfiles that yielded a fileset and produced no errors
    q = '''SELECT {:s} FROM {:s}
           WHERE {:s} IS NOT null
           AND {:s} IS NULL'''
    q = q.format(fileid, table, contents, error)

    results = list(db.dbcon.cursor().execute(q))

    for restpl in results:
        fileid = restpl[0]
        yield fileid


def _unprocessed_file_ids(db):
    ''' generates file_ids that have not yet been processed as zipfile '''

    # prepare query for files with proper mimetype or substring in magic
    libmagictable = db.get_tblname(_libmagicmodel.MODELNAME)
    mimetype = db.get_colname(_libmagicmodel.MODELNAME, 'mimetype')
    libmagic = db.get_colname(_libmagicmodel.MODELNAME, 'libmagic')
    fileid = db.get_colname(_libmagicmodel.MODELNAME, 'file')
    mimes = ['{:s}.{:s} == "{:s}"'.format(libmagictable, mimetype, t) for t in ZIP_MIMES]
    where = ' OR '.join(mimes)
    candidates = 'SELECT {:s}.{:s} FROM {:s} WHERE ({:s})'.format(libmagictable, fileid, libmagictable, where)

    # and we need only those files that are not already extracted
    my_table = db.get_tblname(MODELNAME)
    my_fileid = db.get_colname(MODELNAME, 'file')
    processed_files = 'SELECT {:s}.{:s} FROM {:s}'.format(my_table, my_fileid, my_table)

    # exclude files that already have children (i.e. already decompressed?)
    parenttbl = db.get_tblname(_fparentmodel.MODELNAME)
    parentid = db.get_colname(_fparentmodel.MODELNAME, 'parent')
    parents = 'SELECT {:s}.{:s} FROM {:s}'.format(parenttbl, parentid, parenttbl)

    # select those files that are not processed and are not parents
    q = '''{:s} AND ({:s}.{:s} NOT IN ({:s})) AND ({:s}.{:s} NOT IN ({:s}))'''
    q = q.format(candidates, libmagictable, fileid, processed_files, libmagictable, fileid, parents)

    # fetch all results and store in a list of file ids and use dedicated
    # cursor to prevent issues with aborted SELECT statements
    results = [r[0] for r in db.dbcon.cursor().execute(q)]
    return results


def _unzipround(db, whitelist, progress):
    ''' unpack currently unprocessed zipfiles '''

    todolist = _unprocessed_file_ids(db)

    if len(todolist) == 0:
        return 0

    if progress is True:
        todolist = _progresswrapper(todolist, '{:20s}'.format('    zipfile'))

    c = 0
    for id_ in todolist:
        rowid = _insert(db, id_, None, whitelist, False, icall=True)
        c+=1
    return c
