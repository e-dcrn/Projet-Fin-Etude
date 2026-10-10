import struct

import pytest

from app.capture import PcapStream


def pcap(packets, endian="<", nanoseconds=False):
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    data = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    for sec, frac, payload in packets:
        data += struct.pack(endian + "IIII", sec, frac, len(payload), len(payload) + 4) + payload
    return data


def unpack(record):
    sec, usec, captured, original = struct.unpack_from("<IIII", record)
    return sec, usec, captured, original, record[16:]


@pytest.mark.parametrize("endian", ["<", ">"])
def test_split_in_arbitrary_chunks(endian):
    stream = pcap([(10, 5, b"abc"), (11, 6, b""), (12, 7, b"x" * 1500)], endian)
    parser, packets = PcapStream(), []
    for i in range(0, len(stream), 7):  # morceaux de 7 octets : en-têtes et données coupés
        packets += parser.feed(stream[i : i + 7])
    assert [unpack(p) for p in packets] == [
        (10, 5, 3, 7, b"abc"),
        (11, 6, 0, 4, b""),
        (12, 7, 1500, 1504, b"x" * 1500),
    ]


def test_nanosecond_timestamps_are_converted():
    (packet,) = PcapStream().feed(pcap([(1, 123456789, b"z")], nanoseconds=True))
    assert unpack(packet)[:2] == (1, 123456)


def test_invalid_stream():
    with pytest.raises(ValueError):
        PcapStream().feed(b"\x00" * 24)
