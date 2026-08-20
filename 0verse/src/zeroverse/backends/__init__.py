"""Decompiler backends implementing the ILAdapter interface.

The ``contract`` module defines the explicit ``DecompilerBackend`` Protocol +
``ProgramAdapter`` (an ``ILAdapter`` carrying ``ProgramMeta``) and the auto-selector
(``$ZEROVERSE_BACKEND=auto|ghidra|rizin|angr``).

- ``ghidra`` — default, free (Apache-2.0), High P-Code SSA via PyGhidra (highest fidelity).
- ``rizin``  — rizin/radare2 + r2ghidra ``pdg`` pseudo-C; no Java/GHIDRA_HOME (M5 #27).
- ``angr``   — CLE load + angr decompiler; pure-Python pip fallback (M5 #27).
- ``binja``  — optional premium adapter for Binary Ninja license holders (M5, deferred).
"""
