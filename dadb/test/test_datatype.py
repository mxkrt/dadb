''' test_datatype.py - tests for the _datatype module in DADB

Copyright (c) 2023-2025 Netherlands Forensic Institute - MIT License
Copyright (c) 2024-2025 mxkrt@lsjam.nl - MIT License
'''

import datetime
import pytz
from .. import _datatype as dtype

def test_converters():
    ''' test convert functions '''

    a = dtype.from_iso8601('20220116T012345+00:00')
    b = datetime.datetime(2022, 1, 16, 1, 23, 45).replace(tzinfo=pytz.UTC)
    assert a == b, 'from_iso_8601 failed!'

    a = datetime.datetime(2016, 4, 16, 14, 23, 45)
    a = dtype.isoformat(a)
    b = "2016-04-16T14:23:45"
    assert a == b, 'isoformat failed!'
