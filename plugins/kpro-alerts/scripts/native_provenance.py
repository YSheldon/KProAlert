"""Validate a locator only; it is not native source attestation or consent."""
import re

def validate_source(value):
    if (not isinstance(value,dict) or set(value)!={'schema','batchSha256','recordIndex'} or
        value['schema']!='FalconProCollectorSource/v1' or
        not isinstance(value['batchSha256'],str) or not re.fullmatch('[a-f0-9]{64}',value['batchSha256']) or
        type(value['recordIndex']) is not int or not 0<=value['recordIndex']<1024):
        raise ValueError('Invalid native source locator')
    return dict(value)
