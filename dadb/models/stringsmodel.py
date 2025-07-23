''' stringsmodel.py - models and functions related to string searching

Copyright (c) 2023-2025 Netherlands Forensic Institute - MIT License
Copyright (c) 2024-2025 mxkrt@lsjam.nl - MIT License
'''

import multiprocessing as _multiprocessing
import apsw as _apsw
import subprocess as _subprocess
from collections import namedtuple as _nt
import re as _re
import os as _os
from enum import Enum as _Enum

from .. import Database as _Database
from .. import model_definition as _model_def
from .. import field_definition as _field_def
from .. import progresswrapper as _progresswrapper
from .. import exceptions as _exceptions

from . import filemodel as _filemodel


##########
# MODELS #
##########

# model changelog
# 1 - initial version
# 2 - split (large) output into separate records
# 3 - no longer store offset in strings output
# 4 - add fts5 index to speed up search


MODELNAME = 'strings'
MODELDESCRIPTION = 'strings model for DADB'
MODELVERSION = 4


class StringType(_Enum):
    ''' the width and endianness of the search results '''

    Sevenbit = 1
    Eightbit = 2
    LittleEndian16bit = 3
    BigEndian16bit = 4
    LittleEndian32bit = 5
    BigEndian32bit = 6


modeldef = _model_def(MODELNAME,
                     [_field_def('file', _filemodel.modeldef, nullable=False),
                      _field_def('offset', int, nullable=False),
                      _field_def('encoding', StringType, nullable=False),
                      _field_def('error', str),
                      _field_def('strings', str)],
                     MODELDESCRIPTION, MODELVERSION,
                     fail_on_dup=False)


# search results (with offset, lenght and bytes)
_searchres = _nt('search_result', 'fileid offset length bytes')

# blocksize to use when running the strings command (default 50MB)
BLOCKSIZE=50*1024*1024

# default max size of a search hit when searching for string patterns
DEFAULT_HIT_SPAN=4096

# upper limit of the size of individual search hits
MAX_HIT_SPAN=16384

# encodings to try when scanning files with regexes to find exact matches
encodings = ['ascii', 'utf8', 'latin_1', 'utf16']


#######
# API #
#######


def register_with_db(db):
    ''' register the models covered by this module '''

    _filemodel.register_with_db(db)
    db.register_enum(StringType, MODELDESCRIPTION, MODELVERSION)
    db.register_model(modeldef)


def insert(db, fileid):
    ''' run strings on the file with the given id and add results to database.
    '''

    # check if the file has already been processed
    query = _rowid_by_fileid_query(db)
    results = _get_rowids(db, fileid, query)
    if results != None:
        return results

    # get the file, or raise exception if model or item does not exist
    f = db.modelitem(_filemodel.MODELNAME, fileid)

    # silently ignore files with no data or non-regular files
    if f.ftype.value != _filemodel.Filetype.regular_file.value:
        return None
    if f.size == 0:
        return None
    if f.data is None:
        return None
    if f.data.stored is False:
        return None

    # make sure everything happens in a single transaction
    started_transaction = db.begin_transaction()

    rowids = []

    try:
        # 7-bit strings
        for offset, results, error in _process_file(f, encoding='s'):
            m = db.make_modelitem(MODELNAME, file=fileid, offset=offset,
                                  encoding=StringType.Sevenbit,
                                  error=error, strings=results)
            rowid = db.insert_modelitem(m)
            rowids.append(rowid)

        # 8-bit strings
        for offset, results, error in _process_file(f, encoding='S'):
            m = db.make_modelitem(MODELNAME, file=fileid, offset=offset,
                                  encoding=StringType.Eightbit,
                                  error=error, strings=results)
            rowid = db.insert_modelitem(m)
            rowids.append(rowid)

        # 16-bit little endian strings
        for offset, results, error in _process_file(f, encoding='l'):
            m = db.make_modelitem(MODELNAME, file=fileid, offset=offset,
                                  encoding=StringType.LittleEndian16bit,
                                  error=error, strings=results)
            rowid = db.insert_modelitem(m)
            rowids.append(rowid)

    except:
        if started_transaction is True:
            db.rollback_transaction()
        raise

    if started_transaction is True:
        db.end_transaction()

    return rowids


def get(db, object_id):
    ''' returns the modelitem by its object_id '''

    try:
        return db.modelitem(MODELNAME, object_id)
    except _exceptions.NoSuchModelItemError:
        return None


def items(db, with_pkey=False):
    ''' yield modelitems '''

    return db.modelitems(MODELNAME, with_pkey)


def update(db, progress=False):
    ''' collect strings for unprocessed files '''

    db.check_registered(MODELNAME)

    # make sure we end existing transactions so that we have a proper
    # view of the current state of the database before determining
    # the list of unprocessed files
    try:
        db.end_transaction()
    except _apsw.SQLError as e:
        if e.args[0] == 'SQLError: cannot commit - no transaction is active':
            pass
        else:
            raise

    # collect the todolist
    todolist = list(_unprocessed_file_ids(db))

    if len(todolist) == 0:
        return

    # First process the large files in the main thread. The rationale here is
    # that with multiprocessing, the results need to be communicated between the
    # sub threads and the main thread and we want to prevent having to place very
    # large result sets into the queue. So we only process files that are
    # smaller than the chosen blocksize via multiprocessing.

    # results into the result queue
    large_files = []
    for fid in todolist:
        f = db.modelitem(_filemodel.MODELNAME, fid)
        if f.size > BLOCKSIZE:
            large_files.append(fid)

    if progress is True:
        # create a fake sequence wrapped in progresswrapper
        todolist = _progresswrapper(large_files, '{:20s}'.format('    strings (large files)'))

    # insert the results into the database in one transaction
    db.begin_transaction()
    try:
        for fileid in todolist:
            insert(db, fileid)
    except:
        db.rollback_transaction()
        raise
    db.end_transaction()

    # next, process the small files using multiprocessing
    _update_multiproc(db, progress)

    # rebuild the FTS index
    if _has_fts(db):
        if progress is True:
            print('    rebuilding FTS5 index...', end='', flush=True)
        _rebuild_fts_index(db)
        if progress is True:
            print('done')


def search(db, string, use_fts=False, files_only=False, max_span=DEFAULT_HIT_SPAN):
    ''' search for the given search terms all the files in the database

    Arguments:

    - string     : the term(s) used in the search, separated by asterisks (*)
    - use_fts    : if True, use full text search (FTS) instead of LIKE queries
    - files_only : instead of yielding individual hits, yield file ids
    - max_span   : the max size of the search hit (default 4K, max 16K)

    Search works as follows:

    1. The given search terms are searched in the output generated by the
       'strings' command in order to find candidate files.

    2. The search terms are converted to regular expressions using the several
       string encodings (currently ascii, utf8, latin_1 and utf16)

    3. The candidate files are scanned using the regular expressions generated
       in step 2 in order to obtain exact matches in the original file data.

    Caveats:

    - Isolated strings (strings separated by non-printable characters) smaller
      than 4 characters can not be found, since the strings command used to
      detect strings in file data uses a minimal length of 4 characters.

    - When search terms separated by asterisks (*) are so far apart that the
      entire result length exceeds max_span, the results will not be yielded.

    - There is a tradeoff between search speed and result completeness
      when using FTS search (use_fts=True). See additional comments below.

    - Files are scanned for seven bit, eight bit and 16 bit little-endian
      encodings, via the strings command. Other encodings (big-endian, 32-bit)
      are not indexed, so we can not search for those.

    - Candidate files are scanned via regexes using ascii, utf8, latin_1 and
      utf16 encodings. Strings in other encodings can not be found.

    Additional notes on FTS search:

    Using FTS may speed up the search significantly (if a search index has been
    created first). However, you should be aware that in this case a tokenizer
    is used that may result in missing some results. This is caused by the fact
    that the FTS index contains keywords (separated by the tokenizer) and that
    we can only match our search terms on the entire keyword (or at the start
    of a keyword if an asterisk is used after the search term).

    As a consequence: using FTS one can not find terms that (only) occur
    somewhere in the middle of some larger keyword. To illustrate: when a file
    contains the word 'somestring', using FTS we can not find it by searching
    for 'mestri', whereas it can be found using the slower search without FTS.

    In addition to this, when separating two terms with an asterisk (*) in the
    search string, the FTS search only considers results where these terms are
    indeed two separate tokens. To illustrate, when searching for the terms
    'content*protection', the result that contains 'contentprotection' will not
    be found via the FTS search. It can, however, be found using the slower
    search without FTS
    '''

    if max_span > MAX_HIT_SPAN:
        raise ValueError('max_span can not exceed {:d}!'.format(MAX_HIT_SPAN))

    if use_fts is False:
        # first find files that contain the given search terms
        candidates = _get_candidates(db, string)
    else:
        if not _has_fts(db):
            raise ValueError('enable FTS before using use_fts=True')

        phrase = _string_to_fts_phrase(string)
        candidates = _fts_candidates(db, phrase)

    # for each candidate determine the location of search hits
    for id_ in candidates:
        if files_only is True:
            has_match = _get_matches(db, id_, string, max_span, True)
            if has_match:
                yield id_
                continue
        else:
            ranges = _get_matches(db, id_, string, max_span)
            ranges.sort()
            for offset, length in ranges:
                f = _filemodel.get(db, id_)
                f.data.seek(offset)
                data = f.data.read(length)
                yield _searchres(id_, offset, length, data)
    return


def enable_fts(db, progress=False):
    ''' enable FTS search capabilities on the strings output '''

    _create_fts_index(db)
    if progress is True:
        print('    building FTS5 index...', end='', flush=True)
    _rebuild_fts_index(db)
    if progress is True:
        print('done')


##################
# regex scanning #
##################


def _build_regexes(string, hit_span):
    ''' create regular expressions to search for given string '''

    # split search terms separated by wildcard
    components = string.split('*')
    # remove empty components (if wildcard is at start or end)
    components = [c for c in components if c != '']

    # The distance between individual search terms separated by a wildcard (*)
    # should be limited to prevent finding matches that exceed the max span
    # of a search hit. Since we know the size of each term we can
    # We know the size of each component, which we can subtract from the
    # maximum size of a search hit to get the theoretical maximum distance
    # between the terms (in bytes).
    size = sum([len(c) for c in components])
    max_distance = hit_span - size

    # use the max distance between words to limit the search
    filler = '.{{0,{:d}}}?'.format(max_distance)
    filler = filler.encode()

    # create regex for each encoding
    regexes = []
    for enc in encodings:
        try:
            if enc == 'utf16':
                terms = [c.encode(enc)[2:] for c in components]
                regex = filler.join(terms)
            else:
                terms = [c.encode(enc) for c in components]
                regex = filler.join(terms)
            # compile with DOTALL flags to make sure we match string
            # patterns that contain non-printables and with IGNORECASE
            # to match on lower and upper case hits
            regexes.append(_re.compile(regex,flags=_re.S|_re.I))
        except:
            regexes.append(None)

    # drop empty and equal regexes
    regexes = list(set([r for r in regexes if r is not None]))
    return regexes


def _get_matches(db, fileid, string, max_span, has_match_only=False):
    ''' return (offset, size) tuples for each search hit in file data '''

    # check if max_span does not exceed maximum
    if max_span > MAX_HIT_SPAN:
        raise ValueError("max_span is limited to {:d}".format(MAX_HIT_SPAN))

    regexes = _build_regexes(string, max_span)

    # get the file
    f = _filemodel.get(db, fileid)

    # read the first block
    block = f.data.read(BLOCKSIZE)
    blockstart = 0
    # keep track of the unique matches in all blocks
    unique_matches = set()
    while block != b'':
        # get the current position
        pos = f.data.tell()
        if has_match_only is True:
            if _block_has_match(block, regexes, max_span):
                return True
        else:
            sub_matches = _scan_block(block, blockstart, regexes, max_span)
            unique_matches = unique_matches.union(sub_matches)

        # abort if we have reached the end of the file
        if pos == f.size:
            break

        # seek back max_span bytes and read the next block
        blockstart = pos - max_span
        f.data.seek(blockstart)
        block = f.data.read(BLOCKSIZE)

    if has_match_only is True:
        return False
    else:
        return list(unique_matches)


def _scan_block(block, offset, regexes, max_span):
    ''' search the given block for given regexes '''

    unique_matches = set()

    for regex in regexes:
        matches = regex.finditer(block)
        for match in matches:
            start,end = match.span()
            if end-start > max_span:
                # result is too long, skip
                continue
            unique_matches.add((start+offset, end-start))
    return unique_matches


def _block_has_match(block, regexes, max_span):
    ''' search the given block for given regexes '''

    for regex in regexes:
        matches = regex.finditer(block)
        for match in matches:
            start,end = match.span()
            if end-start > max_span:
                # result is too long, skip
                continue
            return True
    return False


################
# basic search #
################


def _like_query(search_string):
    ''' convert the given search term(s) to LIKE query '''

    # split into components separated by wildcard
    components = search_string.split('*')
    # remove empty components (if wildcard is at start or end)
    components = [c for c in components if c != '']
    # create query string
    qstring = '%'.join(components)
    qstring = '%'+qstring+'%'
    return qstring


def _get_candidates(db, string):
    ''' get files that match the given search string pattern'''

    qstring = _like_query(string)

    # we use direct queries, so check model existence ourselves
    db.check_registered(MODELNAME)

    # perform the SQLite query to get files with a match
    q = _candidate_query(db)
    c = db.dbcon.cursor()
    c.execute(q, (qstring,))

    for fileid in c:
        yield fileid[0]


def _candidate_query(db):
    ''' return query to get files with specific strings '''

    tbl = db.get_tblname(MODELNAME)
    idcol = db.get_colname(MODELNAME)
    filecol = db.get_colname(MODELNAME, 'file')
    stringcol = db.get_colname(MODELNAME, 'strings')

    q = 'SELECT {:s} FROM {:s} WHERE {:s} LIKE ? GROUP BY {:s}'
    return q.format(filecol, tbl, stringcol, filecol)


###############
# fts5 search #
###############


def _has_fts(db):
    ''' return True if fts is enabled '''

    tblname = db.get_tblname(MODELNAME)

    # check if an fts_strings table already exists
    Q = "SELECT * FROM sqlite_master WHERE name = 'fts_{:}'".format(tblname)
    res = list(db.dbcur.execute(Q))
    if len(res) > 0:
        return True
    return False


def _create_fts_index(db):
    ''' create a fts5 index on the strings table '''

    if _has_fts(db):
        return

    # the query to create an external content table
    Q = "CREATE VIRTUAL TABLE fts_{:} USING fts5({:}, content='{:}', content_rowid='{:}');"
    tblname = db.get_tblname(MODELNAME)
    content_rowid = db.get_colname(MODELNAME)
    strings_fld = db.get_colname(MODELNAME, 'strings')
    Q = Q.format(tblname,strings_fld, tblname, content_rowid)
    db.dbcur.execute(Q)


def _rebuild_fts_index(db):
    ''' rebuild the entire fts index from scratch '''

    if not _has_fts(db):
        raise ValueError('enable FTS first!')

    Q = "INSERT INTO fts_{:}(fts_{:}) VALUES('rebuild')list;"
    Q = "INSERT INTO fts_{:}(fts_{:}) VALUES('rebuild');"
    tblname = db.get_tblname(MODELNAME)
    Q = Q.format(tblname,tblname)
    db.dbcur.execute(Q)


def _string_to_fts_phrase(string):
    ''' convert the search string to a proper FTS phrase '''

    # translate the provided keyword(s) into a FTS query
    components = string.split('*')
    # remove empty components (if wildcard is at start or end)
    components = [c for c in components if c != '']
    # add quotes to each component
    components = ['"'+c+'"' for c in components]
    # combine into a single fts_query
    phrase = '*'.join(components)
    # add a final asterisk to allow last token to be prefix token
    phrase += '*'
    return phrase


def _fts_candidates(db, fts_query):
    ''' return list of fileids that match the given fts query

    The fts_query is passed verbatim as argument to the MATCH operator.
    See: https://sqlite.org/fts5.html for details on the query syntax.

    The fts_query must be given as single-quoted string, because the double
    quote has a special meaning in FTS5 query syntax (this is used to define a
    phrase). This means that single-quotes within the fts_query argument should
    be escaped with the backslash character. Double quotes in the search query
    should be escaped SQL-style, by adding a second double-quote.
    '''

    tblname = db.get_tblname(MODELNAME)
    q = "SELECT rowid FROM fts_{:} WHERE fts_{:} MATCH ?"
    q = q.format(tblname, tblname, fts_query)
    dbcur = db.dbcon.cursor()
    # the rowids of the string entries
    rowids = [r[0] for r in dbcur.execute(q, (fts_query,))]
    # get the rowids of the corresponding files
    q = 'SELECT {:s} FROM {:s} WHERE {:s} == ?'
    tbl = db.get_tblname(MODELNAME)
    idcol = db.get_colname(MODELNAME)
    filecol = db.get_colname(MODELNAME, 'file')
    stringcol = db.get_colname(MODELNAME, 'strings')
    q = q.format(filecol, tblname, idcol, filecol)
    fileids = set()
    for r in rowids:
        res = list(dbcur.execute(q, (r,)))
        if len(res) != 1:
            raise ValueError('expected single result')
        fileids.add(res[0][0])
    for r in fileids:
        yield r


######################
# strings generation #
######################


def _rowid_by_fileid_query(db):
    ''' build the query to fetch rowids by filied '''
    # get field and table names
    mtbl = db.get_tblname(MODELNAME)
    mfid = db.get_colname(MODELNAME, 'file')
    mkey = db.get_colname(MODELNAME)
    return 'SELECT {:s} FROM {:s} WHERE {:s} == ?'.format(mkey, mtbl, mfid)


def _get_rowids(db, fileid, query):
    ''' return rowids of results for given fileid '''

    results = list(db.dbcon.cursor().execute(query, (fileid,)))
    if len(results) == 0:
        return None
    results = [r[0] for r in results]
    return results


def _process_block(block, encoding='s'):
    ''' feed a single block (bytes) into the strings command '''

    # run the strings command on the given block
    proc = _subprocess.Popen(['strings', '-e', encoding],
                             stdin=_subprocess.PIPE, stdout=_subprocess.PIPE,
                             stderr=_subprocess.PIPE)
    stdout, stderr = proc.communicate(block)

    # decode the error if present
    error = None
    if stderr != b'':
        # prevent processing broken output, return with error
        return None, stderr.decode()

    # if output is empty, return results
    if stdout == b'':
        return None, error

    # if we get here, we have output, attempt to decode it
    try:
        output = stdout.decode('utf8')
    except UnicodeDecodeError:
        output = None

    if output == None:
        try:
            output = stdout.decode('latin_1')
        except:
            output = None

    # fall back to utf8 with the replace strategy
    if output == None:
        output=stdout.decode(errors='replace')
        error='WARNING: potential replacement characters in output'

    return output, error


def _process_file(f, encoding='s'):
    ''' process the file in a blockwise manner '''

    # reset read pointer
    f.data.seek(0)

    if f.size < BLOCKSIZE:
        out, err = _process_block(f.data.read(), encoding)
        yield 0, out, err
        return

    # Due to reading in a block-wise manner, we need to take
    # care not to miss strings that exist on block boundaries:
    #
    #   block 1          block 2          block 3
    # +----------------+----------------+---------------+
    # | string1     string2   string3  string4 string5  |
    # +----------------+----------------+---------------+
    #               ^                  ^
    # In this example string2 and string4 start before and end after
    # the block boundary. To prevent missing such strings we
    # simply move back MAX_HIT_SPAN bytes and start the next block
    # there. This might lead to some duplicate entries in the strings
    # results, but since we only use the raw strings output as a prelimary
    # filter for finding the files with search hits, this is no problem. Also,
    # we might still miss strings that are longer than MAX_HIT_SPAN at the
    # block boundary, so we make sure MAX_HIT_SPAN is sufficiently large.

    # start at offset 0
    block_offset = 0

    # continue while we have blocks to process
    while block_offset < f.size:

        # read the current block
        f.data.seek(block_offset)
        block = f.data.read(BLOCKSIZE)
        result, error = _process_block(block, encoding)

        if result is not None:
            yield block_offset, result, error

        # check if we processed the last block
        if block_offset + len(block) == f.size:
            return

        # move to the next block
        block_offset += len(block) - MAX_HIT_SPAN


def _update_multiproc(db, progress=False):
    ''' run strings on small files via multiprocessing '''

    # use all cores minus 2
    processes = _multiprocessing.cpu_count() - 2

    # collect the todolist
    todolist = list(_unprocessed_file_ids(db))

    if len(todolist) == 0:
        return

    if progress is True:
        # create a fake sequence wrapped in progresswrapper
        fmt = '    strings (small files)'
        counter = (i for i in _progresswrapper(range(len(todolist)), '{:20s}'.format(fmt)))

    task_queue = _multiprocessing.Queue()
    done_queue = _multiprocessing.Queue()

    for fileid in todolist:
        task_queue.put(fileid)

    # construct the get_by_fileid query only once
    query = _rowid_by_fileid_query(db)

    # Start worker processes
    workers = []
    for i in range(processes):
        p = _multiprocessing.Process(target=_multiproc_worker, args=(db, task_queue, done_queue, query))
        workers.append(p)
        p.start()

    # insert the results into the database in one transaction
    db.begin_transaction()

    # collect the results
    c = 0
    try:
        for i in range(len(todolist)):
            res = done_queue.get()
            c+=1
            if progress is True:
                # update the progress counter
                next(counter)
            if res is None:
                continue
            # create and insert the 7bit result modelitem
            m = db.make_modelitem(MODELNAME, file=res[0], offset=0,
                                  encoding=StringType.Sevenbit,
                                  error=res[2], strings=res[1])
            rowid = db.insert_modelitem(m)
            # create and insert the 8bit result modelitem
            m = db.make_modelitem(MODELNAME, file=res[0], offset=0,
                                  encoding=StringType.Eightbit,
                                  error=res[4], strings=res[3])
            rowid = db.insert_modelitem(m)
            # create and insert the 16bit le result modelitem
            m = db.make_modelitem(MODELNAME, file=res[0], offset=0,
                                  encoding=StringType.LittleEndian16bit,
                                  error=res[6], strings=res[5])
            rowid = db.insert_modelitem(m)
    except:
        db.rollback_transaction()
        raise

    db.end_transaction()

    if progress is True:
        # make sure progress bar indicates 100% when done :)
        list(counter)

    if c != len(todolist):
        raise Exception("incorrect number of results obtained")

    # Tell child processes to stop
    donelist = []
    for i in range(processes):
        task_queue.put('STOP')
        donelist.append(done_queue.get())

    # verify if all workers received the STOP command
    if donelist != ['DONE']*processes:
        raise Exception("not all workers are done")

    # make sure all worker processess are cleaned up
    for p in workers:
        p.join()


def _multiproc_worker(db, input, output, query):
    ''' run strings on a single file '''

    # make new connection to the database, make sure to only
    # access read-only by not registering the models
    subdb = _Database(db.dbname)
    subdb.load()

    for fileid in iter(input.get, 'STOP'):
        existing = _get_rowids(subdb, fileid, query)
        if existing is not None:
            output.put(None)
            continue

        # get the file, or raise exception if model or item does not exist
        f = subdb.modelitem(_filemodel.MODELNAME, fileid)

        # default values
        sevenbit_o = None
        sevenbit_e = None
        eightbit_o = None
        eightbit_e = None
        le16bit_o = None
        le16bit_e = None

        if f.ftype.value != _filemodel.Filetype.regular_file.value:
            pass
        elif f.data is None:
            pass
        elif f.data.stored is False:
            pass
        else:
            sevenbit = list(_process_file(f, encoding='s'))
            eightbit = list(_process_file(f, encoding='S'))
            le16bit = list(_process_file(f, encoding='l'))
            # TODO: can we drop these checks for optimization?
            if len(sevenbit) != 1:
                raise ValueError("expected only single result")
            if len(eightbit) != 1:
                raise ValueError("expected only single result")
            if len(le16bit) != 1:
                raise ValueError("expected only single result")

            offset, sevenbit_o, sevenbit_e = sevenbit[0]
            # TODO: can we drop this check?
            if offset != 0:
                raise ValueError("expected offset 0")
            offset, eightbit_o, eightbit_e = eightbit[0]
            # TODO: can we drop this check?
            if offset != 0:
                raise ValueError("expected offset 0")
            offset, le16bit_o, le16bit_e = le16bit[0]
            # TODO: can we drop this check?
            if offset != 0:
                raise ValueError("expected offset 0")

        output.put((fileid, sevenbit_o, sevenbit_e, eightbit_o,
                    eightbit_e, le16bit_o, le16bit_e))

    # not really needed, since process will be killed, but do it anyway
    subdb.close()
    subdb = None
    # put DONE when STOP is received
    output.put('DONE')


def _unprocessed_file_ids(db):
    ''' generates file_ids that are not yet processed '''

    # we need primary key from file table and 'file' column from our model table
    ftbl = db.get_tblname(_filemodel.MODELNAME)
    fid = db.get_colname(_filemodel.MODELNAME)
    mtbl = db.get_tblname(MODELNAME)
    mfid = db.get_colname(MODELNAME, 'file')
    # we are only interested in regular files...
    ftype = db.get_colname(_filemodel.MODELNAME, 'ftype')
    regular = _filemodel.Filetype.regular_file.value
    # ...that are not empty
    fsize = db.get_colname(_filemodel.MODELNAME, 'size')

    # select those files which have no entry in mimetype table
    q = '''SELECT {:s}.{:s} FROM {:s}
           WHERE {:s}.{:s} NOT IN
           (SELECT {:s}.{:s}
           FROM {:s}) AND {:} is {:} AND {:} is not 0'''
    q = q.format(ftbl, fid, ftbl, ftbl, fid, mtbl, mfid, mtbl,
                 ftype, regular, fsize)

    # NOTE: use a dedicated cursor to prevent nesting issues
    results = db.dbcon.cursor().execute(q)

    for restpl in results:
        fileid = restpl[0]
        yield fileid
