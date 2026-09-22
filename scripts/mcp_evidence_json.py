"""Unambiguous UTF-8 JSON for Inspector's native MCP evidence readers."""
import json
import math


def loads(raw):
    def object_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate JSON key: '+key)
            value[key] = item
        return value

    def constant(value):
        raise ValueError('non-finite JSON number: '+value)

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            return constant(value)
        return result

    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode('utf-8')
    return json.loads(raw, object_pairs_hook=object_pairs,
                      parse_constant=constant, parse_float=finite_float)
