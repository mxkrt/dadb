# dadb - Data Analysis DataBase

DADB is a simple database framework that can be used to store "Data" and
"Models" in a single SQLite database. It is intended to solve a basic
requirement that is common in Data Analysis: storing and combining results of
various different analysis tools for futher (combined) analysis. DADB is not a
tool but a module that you can use in your own projects.

## Basic concepts

DADB is a database framework that can be used to store "Data" and "Models" in a
single SQLite database. Data objects are binary blobs of arbitrary size data
that can be used as file-like objects. Models are ways to store user-defined
objects that consist of one or more member fields. An object that is stored in a
model in the database is considered a "modelitem". Each member field can hold
(a sequence of) one of the basic datatypes:

* DateTime
* Date
* Integer
* String
* Bytes
* Bool
* TimeDelta
* Float

In addition, a member field can hold (a sequence of) the following:

* a Data object
* an Enum value
* a modelitem of some other model.

Models can be defined in Python code in a simple language. A model for storing
a 'measurement', for example, could look something like this:

    modeldef = model_definition('measurement',
                                [field_definition('name', str, nullable=False),
                                 field_definition('tstart', _datetime),
                                 field_definition('tend', _datetime),
                                 field_definition('samplecount', int, nullable=False),
                                 field_definition('samples, (int,)),
                                 field_definition('category', Category, nullable=False),
                                 field_definition('raw_data', Data),
                                 field_definition('notes', str)],
                                'measurement model',
                                1,
                                implicit_dedup=True,
                                fail_on_dup=True)

Here, Category is an enum that needs to be defined separately. For an
explanation of the other parts of a model definition, please read the
documentation of the model_definition function

## Status

This is an experimental framework that may contain bugs or other problems that
emerge in your specific usage scenario. Please perform thorough testing and
validation before relying on any results.

## Caveats

When using DADB you should take care of the following:

* DADB is intended for use on a single analysis computer and for best
  performance the database should be stored on a local HDD (or preferably SSD).

* Make sure the database is written to from a single process only. When you
  want to inspect the results in a viewer such as sqlitebrowser during
  analysis, make sure to open the database read-only.

* DADB is not intended to process very large amounts of data. While DADB is
  reasonably fast, processing large amounts of data or modelitems can take a
  lot of time.

* Documentation and examples are not yet available.

## Standard models ##

The power of dadb is that you can define your own models that are relevant to
your analysis. However, several models are included to provide some basic
functionality. These models are:

* filemodel - used to store file (meta-) data
* fileparentmodel - used to define parent/child relations between files
* filesetmodel - used to group a set of files into a set of files
* libmagicmodel - used to detect and store the type of each file
* zipmodel - used to extract zip files and store the contents as file items
* archivemodel - used to extract some other archive formats into file items
* decompressmodel - used to decompress some compressed file types
* stringsmodel - extract strings from files and provide search functionality

## Usage example ##

This section contains a basic usage example using the built-in models.

Create and initialize a database:

    In [1]: import dadb

    In [2]: db = dadb.Database('/tmp/files.db')

    In [3]: db.create()

    In [4]: dadb.register_all_models(db)

Insert a zipfile from the local filesystem:

    In [5]: fileid, zipid = dadb.zipmodel.insert_local_file(db, '/tmp/testfiles.zip
       ...: ', progress=True)
        unzip: /tmp/testfiles.zip
        - hashing and inserting metadata...done
        extracting      : 100%|█████████████████| 296/296 [00:11<00:00, 25.86 rec/s]
        insert files    : 100%|██████████████| 296/296 [00:00<00:00, 38313.60 rec/s]
        fileparent      : 100%|██████████████| 296/296 [00:00<00:00, 16146.41 rec/s]

We now have a database with 297 files (including the zipfile):

    In [6]: dadb.filemodel.file_count(db)
    Out[6]: 297

We can obtain and inspect one of the files by (part of) its name:

    In [7]: files = dadb.filemodel.get_by_path(db, '*sqlite*')

    In [8]: f = next(files)

    In [9]: f.path
    Out[9]: 'sqlite-amalgamation-3330000.zip'

We can look at some file properties, or access its contents as a file-like
object:

    In [10]: f.mtime, f.size
    Out[10]: (datetime.datetime(2020, 9, 10, 7, 56, 24, tzinfo=tzutc()), 2417079)

    In [11]: f.data.seek(0)

    In [12]: f.data.read(20)
    Out[12]: b'PK\x03\x04\n\x00\x00\x00\x00\x00X\xa5\x0eQ\x00\x00\x00\x00\x00\x00'

As we can see, the file itself is also a zip-file. Let's unpack all zip-files
recursively (with a maximum of 5 unzip rounds), which gives us a database with
139536 files:

    In [13]: dadb.zipmodel.update(db, progress=True, maxrounds=5)
        libmagic        : 100%|███████████████| 294/294 [00:00<00:00, 1731.58 rec/s]
        zipfile         : 100%|███████████████████| 29/29 [00:11<00:00,  2.45 rec/s]
        libmagic        : 100%|██████████| 11357/11357 [00:01<00:00, 10529.53 rec/s]
        zipfile         : 100%|█████████████████| 199/199 [00:20<00:00,  9.66 rec/s]
        libmagic        : 100%|████████| 116265/116265 [00:07<00:00, 15275.22 rec/s]
        zipfile         : 100%|███████████████████| 13/13 [00:00<00:00, 30.60 rec/s]
        libmagic        : 100%|███████████████| 855/855 [00:00<00:00, 1857.04 rec/s]

    In [14]: dadb.filemodel.file_count(db)
    Out[14]: 139536

As can be seen, after each unzip round, the libmagic model is executed to
determine if there are any new zipfiles encountered within the unpacked
zipfiles. The libmagic model can also be used to obtain all files of a specific
type:

    In [15]: png_files = dadb.libmagicmodel.get_by_mimetype(db, 'image/png')

    In [16]: entry = next(png_files)

    In [17]: entry.file.path
    Out[17]: 'Docs/Chm/help/images/b16x16_filesaveas.png'

    In [18]: entry.libmagic
    Out[18]: 'PNG image data, 16 x 16, 8-bit/color RGBA, non-interlaced'

    In [19]: entry._fields
    Out[19]: ('file', 'libmagic', 'mimetype')

The above example shows that the libmagic modelitem has a field called 'file'
that contains the actual file with the corresponding mimetype. We can also
access it's data:

    In [20]: entry.file.data.read(20)
    Out[20]: b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10'

It is not hard to imagine that this can be used to perform some analysis on
files of a specific type. The results can then theoretically be stored into the
same database for further analysis. In this case you would have to define your
own model that can hold the analysis results and use its 'insert' function to
add the results to the database. This is not part of this basic example.

One other functionality that may be of interest is the search functionality
provided by the stringsmodel. Let's extract all strings from each files so we
can search for some strings. Note that this can take a while, although for
small files DADB uses all the cores to perform the string extraction:

    In [21]: dadb.stringsmodel.update(db, progress=True)
        strings (large files): 100%|██████████████| 22/22 [01:03<00:00,  2.89s/ rec]
        strings (small files): 100%|████| 128750/128750 [01:26<00:00, 1493.68 rec/s]

Now we can start looking for files that contain a specific string:

    In [22]: results = dadb.stringsmodel.search(db, 'Torvalds')

    In [23]: next(results)
    Out[23]: search_result(fileid=6940, offset=19435, length=8, bytes=b'Torvalds')

Note that this search method can take some time, since it uses the underlying
'LIKE' query within SQLite3. To speed up the search, one could enable fts5 in
the stringsmodel, although the generation of this index may take a long time.
So there is a tradeoff between the time it takes to perform individual searches
and the time it takes to initialize the stringsmodel. Note that there are other
caveats with the search functionality, read the docstring in the stringsmodel
search function for details).

Enable fts5 as follows and then perform the same search again with an
additional argument:

    In [24]: dadb.stringsmodel.enable_fts(db)

    In [25]: results = dadb.stringsmodel.search(db, 'Torvalds', use_fts=True)

    In [26]: next(results)
    Out[26]: search_result(fileid=117860, offset=19435, length=8, bytes=b'Torvalds')

Note that the order in which results are returned are not equal between the two
different approaches. 

This concludes a basic usage example. A more elaborate tutorial on how to use
DADB within other projects and how to create and use your own models is not yet
available. Please read the documentation in the code to get an idea about this.

## Installation

Checkout the repository and run the following from the root of the checked-out
repository:

    make venv

This will create a virtualenv in ~/.virtualenvs/dadb where dadb can be
installed. Alternatively, you can create your own virtualenv or use an existing
virtualenv.  After activating the proper virtualenv, install dadb usign the
following command:

    make install

## License

Copyright (c) 2023-2025 Netherlands Forensic Institute - MIT License
Copyright (c) 2024-2025 mxkrt@lsjam.nl - MIT License
