"""Slicer + source→sink path finding, exercised over the MockAdapter.

Models the canonical bug: data from ``read(fd, buf, n)`` (source) flows into
``memcpy(dst, buf, n)`` (sink). The slicer must find that the sink's backward
slice reaches the source.
"""

from zeroverse.il import Inst, Kind, MockAdapter
from zeroverse.slicer import BackwardSlicer, find_source_to_sink


def _model():
    insts = [
        # source: read(fd, &buf, n) — defines the tainted buffer `buf`
        Inst(1, "main", 0x1000, Kind.CALL, dest="read", args=[20, 21, 22]),
        Inst(20, "main", 0x1000, Kind.CONST, text="fd"),
        Inst(21, "main", 0x1000, Kind.CONST, text="&buf"),
        Inst(22, "main", 0x1000, Kind.CONST, text="n"),
        # uses
        Inst(2, "main", 0x1010, Kind.VAR, var="buf"),
        Inst(3, "main", 0x1014, Kind.VAR, var="dst"),
        Inst(4, "main", 0x1018, Kind.CONST, text="n"),
        # sink: memcpy(dst, buf, n) — arg operand 2 is the tainted buf
        Inst(10, "main", 0x1020, Kind.CALL, dest="memcpy", args=[3, 2, 4]),
        # an unrelated sink whose args are all constants (no taint)
        Inst(11, "main", 0x1030, Kind.CALL, dest="strcpy", args=[30, 31]),
        Inst(30, "main", 0x1030, Kind.CONST, text="dst2"),
        Inst(31, "main", 0x1030, Kind.CONST, text='"literal"'),
    ]
    defs = {("buf", "main"): 1}  # read() defines buf
    return MockAdapter(insts, defs=defs)


def test_slice_reaches_source():
    slicer = BackwardSlicer(_model())
    sl = slicer.slice(10)            # backward slice of the memcpy sink
    assert 1 in sl.nodes             # reaches the read() source
    assert 2 in sl.nodes             # via the buf use


def test_find_source_to_sink_positive():
    slicer = BackwardSlicer(_model())
    findings = find_source_to_sink(slicer, source_ids=[1], sink_ids=[10, 11])
    # exactly one finding: source 1 (read) -> sink 10 (memcpy)
    assert len(findings) == 1
    f = findings[0]
    assert f.source_id == 1 and f.sink_id == 10
    # path is sink -> ... -> source
    assert f.nodes[0] == 10 and f.nodes[-1] == 1


def test_find_source_to_sink_negative():
    slicer = BackwardSlicer(_model())
    # sink 11 (strcpy of a string literal) has no tainted flow from read
    findings = find_source_to_sink(slicer, source_ids=[1], sink_ids=[11])
    assert findings == []
