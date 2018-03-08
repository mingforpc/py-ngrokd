import struct


def tolen(data):
    if len(data) == 8:
        return struct.unpack('<II', data)[0]
    return 0