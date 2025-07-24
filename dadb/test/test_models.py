''' test_models.py - tests for models in DADB

Copyright (c) 2023-2025 Netherlands Forensic Institute - MIT License
Copyright (c) 2024-2025 mxkrt@lsjam.nl - MIT License
'''

from io import BytesIO as _BytesIO

from . import helpers as _helpers
from .._model_definition import field_definition as _field_def
from .._model_definition import model_definition as _model_def
from .._database import Database as _Database
from .._exceptions import NoSuchDataObjectError as _NoSuchDataObjectError


# work in progress
def _test_modelitem_id(db):
    for f in db.models:
        g = db.modelitems(f, True)
        for (pkey, m) in g:
            if pkey != db.modelitem_id(m):
                raise ValueError('modelitem_id bug detected')
