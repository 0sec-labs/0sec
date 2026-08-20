"""Compile normalized WDM High-P-Code facts into a strict static export.

This boundary performs no driver loading, device access, or execution. Live
acquisition accepts only the complete, directly resolved typed WDM profile
required by :func:`compile_windows_ioctl_high_pcode_facts`.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import tempfile
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

EXPORT_VERSION_V2 = "0verse.windows-ioctl-real-ssa-export/v2"
EXPORT_VERSION_V3 = "0verse.windows-ioctl-real-ssa-export/v3"
RAW_FACT_VERSION_V1 = "0verse.windows-ioctl-normalized-high-pcode-facts/v1"
RAW_FACT_VERSION_V2 = "0verse.windows-ioctl-normalized-high-pcode-facts/v2"
RAW_FACT_VERSION = RAW_FACT_VERSION_V2
EXTRACTOR_PROFILE_V2 = "zeroverse.windows-ioctl-ghidra-high-pcode/v2"
EXTRACTOR_PROFILE = "zeroverse.windows-ioctl-ghidra-high-pcode/v3"
VID_EXTRACTOR_PROFILE = "zeroverse.windows-vid-kmdf-wdm-high-pcode/v1"
VID_DRIVER_SHA256 = "e6934397f003ae94bbe3bf39c97414a992034d7b30849ced584b5ad3cc203a8d"
VID_PDB_SHA256 = "7e1f1a4c9b85617eb91778758a3c3776979ce988c39fac05809e44a763a40562"
VID_CODEVIEW = "2B19AF1D-49FA-D86D-757E-645DE4C0D8A3:1:Vid.pdb"
VID_IOCTL = 0x220054
_CONFIG_V2 = {
    "framework": "wdm",
    "major_function_index": 14,
    "max_dispatches": 128,
    "max_fields_per_dispatch": 64,
    "max_ops_per_dispatch": 16384,
    "max_internal_functions": 4096,
    "max_ops_per_function": 16384,
    "max_total_ops": 262144,
    "max_pdb_structures": 65536,
    "max_taint_path": 256,
    "method": "METHOD_BUFFERED",
    "unresolved_edges": "reject",
}
EXTRACTOR_CONFIG_SHA256_V2 = hashlib.sha256(
    json.dumps(_CONFIG_V2, sort_keys=True, separators=(",", ":")).encode("ascii")
).hexdigest()
_CONFIG = {
    **_CONFIG_V2,
    "guard_semantics": "edge-polarity-and-compound-copy-span-v1",
    "destination_extent": "exact-pdb-or-listing-object",
}
EXTRACTOR_CONFIG_SHA256 = hashlib.sha256(
    json.dumps(_CONFIG, sort_keys=True, separators=(",", ":")).encode("ascii")
).hexdigest()
_VID_CONFIG = {
    "framework": "kmdf-wdm-preprocess",
    "driver_sha256": VID_DRIVER_SHA256,
    "pdb_sha256": VID_PDB_SHA256,
    "ioctl_allowlist": [VID_IOCTL],
    "ghidra_version": "11.3.2",
    "major_function_index": 14,
    "method": "METHOD_BUFFERED",
    "unresolved_edges": "reject",
}
VID_EXTRACTOR_CONFIG_SHA256 = hashlib.sha256(
    json.dumps(_VID_CONFIG, sort_keys=True, separators=(",", ":")).encode("ascii")
).hexdigest()

_SHA256 = re.compile(r"[0-9a-f]{64}")
_HEX = re.compile(r"0x[0-9a-f]+")
_NAME = re.compile(r"[A-Za-z_?$@][A-Za-z0-9_?$@:.<>-]{0,255}")
_ARCHES = {"x86", "x86_64", "arm64"}
_SOURCES = {
    "SystemBuffer": "irp.system_buffer",
    "InputBufferLength": "stack.input_buffer_length",
    "OutputBufferLength": "stack.output_buffer_length",
}
_SINKS = {"copy", "fill", "indexed-store", "allocation"}
_FIELD_KINDS = {"length", "count", "offset", "flags"}
_GUARDS = {
    "input-buffer-length",
    "output-buffer-length",
    "field-within-input",
    "checked-arithmetic",
    "previous-mode",
}
_OPCODES = {
    "BRANCH",
    "CBRANCH",
    "CALL",
    "COPY",
    "CAST",
    "INDIRECT",
    "INT_ADD",
    "INT_AND",
    "INT_EQUAL",
    "INT_LESS",
    "INT_LESSEQUAL",
    "INT_MULT",
    "INT_NOTEQUAL",
    "INT_SLESS",
    "INT_SLESSEQUAL",
    "INT_SUB",
    "INT_ZEXT",
    "LOAD",
    "MULTIEQUAL",
    "PTRADD",
    "PTRSUB",
    "STORE",
    "SUBPIECE",
    "RETURN",
}
_VID_OPCODES = _OPCODES | {"CALLIND", "RETURN"}


def analyze_windows_ioctl_driver(binary: Path, pdb: Path, *, ghidra_home: Path) -> dict[str, Any]:
    """Acquire and compile live facts, or fail closed if typed facts are absent."""
    for path, label in ((binary, "driver"), (pdb, "PDB")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Windows IOCTL {label} must be a regular non-symlink file")
    if ghidra_home.is_symlink() or not ghidra_home.is_dir():
        raise ValueError("Ghidra home must be a regular non-symlink directory")
    if hashlib.sha256(binary.read_bytes()).hexdigest() == VID_DRIVER_SHA256:
        raw = _acquire_vid_high_pcode_facts(binary, pdb, ghidra_home)
        return _compile_windows_ioctl_high_pcode_facts(
            raw, VID_EXTRACTOR_PROFILE, VID_EXTRACTOR_CONFIG_SHA256
        )
    raw = _acquire_normalized_high_pcode_facts(binary, pdb, ghidra_home)
    return compile_windows_ioctl_high_pcode_facts(raw)


def analyze_windows_public_ioctl_driver(
    binary: Path,
    pdb: Path,
    public_pdb_bundle: Path,
    *,
    ghidra_home: Path,
) -> dict[str, Any]:
    """Analyze a stripped public PDB only through its verified PE-keyed route."""
    for path, label in ((binary, "driver"), (pdb, "PDB")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Windows IOCTL {label} must be a regular non-symlink file")
    if ghidra_home.is_symlink() or not ghidra_home.is_dir():
        raise ValueError("Ghidra home must be a regular non-symlink directory")
    from .windows_public_pdb import verify_public_pdb_receipt

    route = verify_public_pdb_receipt(binary, public_pdb_bundle)
    if pdb.resolve() != route.artifact_path.resolve():
        raise ValueError("public IOCTL analysis PDB is not the verified route artifact")
    raw = _acquire_normalized_high_pcode_facts(
        binary, pdb, ghidra_home, public_pdb_bundle=public_pdb_bundle
    )
    compiled = compile_windows_ioctl_high_pcode_facts(raw)
    compiled["pdb_codeview_identity"] = f"{route.pdb_guid}:{route.pdb_age}:stripped"
    return compiled


def _acquire_normalized_high_pcode_facts(
    binary: Path,
    pdb: Path,
    ghidra_home: Path,
    *,
    public_pdb_bundle: Path | None = None,
) -> dict[str, Any]:
    """Acquire WDM facts after proving exact-full or verified public identity."""
    try:
        import pyghidra  # noqa: F401
    except ImportError as exc:
        raise RuntimeError("PyGhidra is unavailable for Windows IOCTL extraction") from exc
    from .pe_symbols import pdb_codeview_identity, pe_codeview_identity

    pe_identity = pe_codeview_identity(binary)
    pdb_identity = pdb_codeview_identity(pdb)
    if public_pdb_bundle is None:
        if (
            pe_identity is None
            or pdb_identity is None
            or pe_identity[:2] != pdb_identity[:2]
        ):
            raise ValueError("live IOCTL extraction requires an exact matching PE/PDB identity")
        if pdb_identity[2]:
            raise ValueError("live IOCTL exact extraction requires a non-stripped PDB")
    else:
        from .windows_public_pdb import verify_public_pdb_receipt

        route = verify_public_pdb_receipt(binary, public_pdb_bundle)
        if pdb.resolve() != route.artifact_path.resolve():
            raise ValueError("public IOCTL acquisition PDB is not the verified route artifact")
        if (
            pe_identity is None
            or pdb_identity is None
            or not pdb_identity[2]
            or (pe_identity[0], pe_identity[1]) != (route.pe_guid, route.pe_age)
            or (pdb_identity[0], pdb_identity[1]) != (route.pdb_guid, route.pdb_age)
        ):
            raise ValueError("public IOCTL acquisition identity differs from its verified route")
    if pe_identity is None:
        raise AssertionError("acquisition identity gate did not establish a PE identity")
    image_base, architecture, pointer_size = _pe_machine(binary)
    direct = _direct_high_pcode_evidence(
        binary,
        pdb,
        ghidra_home,
        "DriverEntry",
        "DispatchDeviceControl",
        image_base=image_base,
    )
    handler_name = cast(str, direct["handler_name"])
    driver_body = cast(str, direct["driver_body"])
    handler_body = cast(str, direct["handler_body"])
    registration_pattern = re.compile(
        rf"MajorFunction\s*\[\s*(?:0x0*e|14)\s*\]\s*=\s*&?\s*{re.escape(handler_name)}\b",
        re.IGNORECASE,
    )
    if registration_pattern.search(driver_body) is None:
        raise ValueError("direct WDM MajorFunction[14] registration was not recovered")
    ioctl_values = {
        int(value, 16)
        for value in re.findall(r"0x[0-9a-fA-F]+", handler_body)
        if int(value, 16) > 0xFFFF
    }
    return _finish_generic_acquisition(
        binary,
        pdb,
        image_base,
        architecture,
        pointer_size,
        direct,
        handler_name,
        handler_body,
        ioctl_values,
    )


def _acquire_vid_high_pcode_facts(
    binary: Path, pdb: Path, ghidra_home: Path
) -> dict[str, Any]:
    """Acquire the exact serviced Vid KMDF-to-WDM allowlist slice."""
    from .pe_symbols import pdb_codeview_identity, pe_codeview_identity

    if hashlib.sha256(binary.read_bytes()).hexdigest() != VID_DRIVER_SHA256:
        raise ValueError("driver is outside the reviewed Vid extractor profile")
    if hashlib.sha256(pdb.read_bytes()).hexdigest() != VID_PDB_SHA256:
        raise ValueError("PDB is outside the reviewed Vid extractor profile")
    pe_identity = pe_codeview_identity(binary)
    pdb_identity = pdb_codeview_identity(pdb)
    if (
        pe_identity is None
        or pdb_identity is None
        or pe_identity[0] != pdb_identity[0]
        or not pdb_identity[2]
        or f"{pe_identity[0]}:{pe_identity[1]}:{pe_identity[2]}" != VID_CODEVIEW
    ):
        raise ValueError("reviewed Vid PE/stripped-PDB identity mismatch")
    if _requested_ghidra_version(ghidra_home) != "11.3.2":
        raise ValueError("reviewed Vid extractor requires Ghidra 11.3.2")
    evidence = _vid_high_pcode_evidence(binary, pdb, ghidra_home)
    raw = {
        "schema_version": RAW_FACT_VERSION_V1,
        "driver_sha256": VID_DRIVER_SHA256,
        "pdb_sha256": VID_PDB_SHA256,
        "pdb_codeview_identity": VID_CODEVIEW,
        "architecture": "x86_64",
        "pointer_size": 8,
        "image_base": "0x140000000",
        "coverage": {
            "framework": "kmdf-wdm-preprocess",
            "scope": {"kind": "ioctl-allowlist", "ioctl_codes": [VID_IOCTL], "exhaustive": True},
            "truncated": False,
            "dynamic_dispatch": False,
            "unresolved_edges": [],
        },
        "dispatches": [evidence],
    }
    _validate_vid_normalized_facts(raw)
    return raw


def _vid_high_pcode_evidence(binary: Path, pdb: Path, ghidra_home: Path) -> dict[str, Any]:
    """Recover and prove the exact Vid callback, dispatch, field, guards, and sink."""
    import pyghidra

    pyghidra.start(install_dir=ghidra_home)
    from ghidra.framework import Application

    _require_active_ghidra_version(str(Application.getApplicationVersion()), "11.3.2")
    image_base = 0x140000000
    with tempfile.TemporaryDirectory(prefix="zeroverse-vid-pcode-") as temporary:
        root = Path(temporary)
        target = root / "Vid.sys"
        shutil.copyfile(binary, target)
        shutil.copyfile(pdb, root / "Vid.pdb")
        with pyghidra.open_program(str(target), analyze=False) as flat:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
            from ghidra.util.task import ConsoleTaskMonitor
            from java.io import File

            program = flat.getCurrentProgram()
            PdbUniversalAnalyzer.setPdbFileOption(program, File(str(root / "Vid.pdb")))
            PdbUniversalAnalyzer.setAllowUntrustedOption(program, False)
            flat.analyzeAll(program)
            monitor = ConsoleTaskMonitor()
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            all_functions = _bounded_functions(program.getFunctionManager().getFunctions(True))
            requested = {
                name: _one_ghidra_function(all_functions, name)
                for name in (
                    "DriverEntry",
                    "VidDeviceAdd",
                    "VidIoControlPreProcess",
                    "VidIoControlDriver",
                )
            }
            decoded = {
                name: _decompile_high(decompiler, function, monitor)
                for name, function in requested.items()
            }
            ops = {name: _high_ops(high) for name, (high, _body) in decoded.items()}

            entry = ops["DriverEntry"]
            device = ops["VidDeviceAdd"]
            preprocess = ops["VidIoControlPreProcess"]
            dispatch = ops["VidIoControlDriver"]
            device_add_ptr = _vid_op(entry, image_base, 0xC90E8, "PTRSUB", 119)
            driver_config = _vid_op(entry, image_base, 0xC916B, "PTRSUB", 1218)
            driver_api_add = _vid_op(entry, image_base, 0xC918A, "INT_ADD", 196)
            driver_api_cast = _vid_op(entry, image_base, 0xC918A, "CAST", 1225)
            driver_api_load = _vid_op(entry, image_base, 0xC918A, "LOAD", 197)
            driver_create = _vid_op(entry, image_base, 0xC9191, "CALLIND", 314)
            _vid_constant(device_add_ptr, 1, 0x14005FFB0)
            _vid_constant(driver_config, 1, 0xFFFFFFFFFFFFFFD8)
            if str(device_add_ptr.getOutput()) != "(stack, 0xffffffffffffffe0, 8)":
                raise ValueError("VidDeviceAdd is not stored in the driver configuration")
            _vid_constant(driver_api_add, 1, 0x3A0)
            _vid_definition(driver_api_cast, 0, driver_api_add)
            _vid_definition(driver_api_load, 1, driver_api_cast)
            _vid_definition(driver_create, 0, driver_api_load)
            _vid_definition(driver_create, 5, driver_config)

            preprocess_ptr = _vid_op(device, image_base, 0x60314, "PTRSUB", 4910)
            registration_api_add = _vid_op(device, image_base, 0x602F4, "INT_ADD", 567)
            registration_api_cast = _vid_op(device, image_base, 0x602F4, "CAST", 4971)
            registration_api_load = _vid_op(device, image_base, 0x602F4, "LOAD", 568)
            registration = _vid_op(device, image_base, 0x60314, "CALLIND", 1076)
            _vid_constant(preprocess_ptr, 1, 0x14002E600)
            _vid_constant(registration_api_add, 1, 0x248)
            _vid_definition(registration_api_cast, 0, registration_api_add)
            _vid_definition(registration_api_load, 1, registration_api_cast)
            _vid_definition(registration, 0, registration_api_load)
            _vid_definition(registration, 3, preprocess_ptr)
            _vid_constant(registration, 4, 14)

            preprocess_call = _vid_op(preprocess, image_base, 0x2E92F, "CALL", 892)
            _vid_address(preprocess_call, 0, 0x140031EA8)
            if preprocess_call.getNumInputs() != 9:
                raise ValueError("Vid preprocess call signature changed")

            ioctl_compare = _vid_op(dispatch, image_base, 0x3213E, "INT_EQUAL", 693)
            ioctl_branch = _vid_op(dispatch, image_base, 0x32140, "CBRANCH", 698)
            ioctl_target = _vid_op(dispatch, image_base, 0x32176, "COPY", 754)
            _vid_name(ioctl_compare, 0, "param_7")
            _vid_constant(ioctl_compare, 1, VID_IOCTL)
            _vid_address(ioctl_branch, 0, 0x140032176)
            _vid_definition(ioctl_branch, 1, ioctl_compare)

            input_length = _vid_op(dispatch, image_base, 0x31ED7, "SUBPIECE", 3499)
            length_compare = _vid_op(dispatch, image_base, 0x3217A, "INT_LESS", 765)
            length_branch = _vid_op(dispatch, image_base, 0x3217E, "CBRANCH", 774)
            _vid_name(input_length, 0, "param_4")
            _vid_constant(length_compare, 0, 7)
            _vid_definition(length_compare, 1, input_length)
            _vid_address(length_branch, 0, 0x1400325A2)
            _vid_definition(length_branch, 1, length_compare)

            buffer_cast = _vid_op(dispatch, image_base, 0x32184, "CAST", 5037)
            field_address = _vid_op(dispatch, image_base, 0x32184, "INT_ADD", 775)
            field_cast = _vid_op(dispatch, image_base, 0x32184, "CAST", 5038)
            field_load = _vid_op(dispatch, image_base, 0x32184, "LOAD", 776)
            _vid_name(buffer_cast, 0, "param_3")
            _vid_definition(field_address, 0, buffer_cast)
            _vid_constant(field_address, 1, 4)
            _vid_definition(field_cast, 0, field_address)
            _vid_definition(field_load, 1, field_cast)
            if field_load.getOutput() is None or int(field_load.getOutput().getSize()) != 4:
                raise ValueError("Vid selected field width changed")

            bound_sub = _vid_op(dispatch, image_base, 0x32188, "INT_SUB", 779)
            bound_compare = _vid_op(dispatch, image_base, 0x3218C, "INT_LESSEQUAL", 783)
            bound_branch = _vid_op(dispatch, image_base, 0x3218F, "CBRANCH", 792)
            _vid_definition(bound_sub, 0, input_length)
            _vid_constant(bound_sub, 1, 8)
            _vid_definition(bound_compare, 0, field_load)
            _vid_definition(bound_compare, 1, bound_sub)
            _vid_address(bound_branch, 0, 0x1400325A2)
            _vid_definition(bound_branch, 1, bound_compare)

            sink = _vid_op(dispatch, image_base, 0x321B0, "CALL", 815)
            failure_status = _vid_op(dispatch, image_base, 0x325AC, "COPY", 212)
            failure_return = _vid_op(dispatch, image_base, 0x325B3, "RETURN", 228)
            _vid_address(sink, 0, 0x1400C5C78)
            _vid_definition(sink, 3, field_load)
            _vid_constant(failure_status, 0, 0xC0000023)
            _vid_definition(failure_return, 1, failure_status)
            high = decoded["VidIoControlDriver"][0]
            _vid_branch_gate(
                high, ioctl_branch, ioctl_target, sink, target_reaches_sink=True
            )
            _vid_branch_gate(
                high, length_branch, failure_status, sink, target_reaches_sink=False
            )
            _vid_branch_gate(
                high, bound_branch, failure_status, sink, target_reaches_sink=False
            )

            selected = [
                device_add_ptr,
                driver_config,
                driver_api_add,
                driver_api_cast,
                driver_api_load,
                driver_create,
                preprocess_ptr,
                registration_api_add,
                registration_api_cast,
                registration_api_load,
                registration,
                preprocess_call,
                ioctl_compare,
                ioctl_branch,
                ioctl_target,
                input_length,
                length_compare,
                length_branch,
                buffer_cast,
                field_address,
                field_cast,
                field_load,
                bound_sub,
                bound_compare,
                bound_branch,
                sink,
                failure_status,
                failure_return,
            ]
            owner = {
                id(op): requested[name]
                for name, values in ops.items()
                for op in values
            }
            references = {
                str(op.getSeqnum()): _operation_ref(op, owner[id(op)], image_base)
                for op in selected
            }
            raw_ops = []
            for op in selected:
                inputs = []
                for index in range(op.getNumInputs()):
                    definition = op.getInput(index).getDef()
                    if definition is not None and str(definition.getSeqnum()) in references:
                        inputs.append(references[str(definition.getSeqnum())])
                inputs = sorted({_ref_token(ref): ref for ref in inputs}.values(), key=_ref_key)
                raw_ops.append({"ref": references[str(op.getSeqnum())], "input_refs": inputs})
            raw_ops.sort(key=lambda item: _ref_key(cast(dict[str, object], item["ref"])))
            def ref(op: Any) -> dict[str, object]:
                return references[str(op.getSeqnum())]

            return {
                "ioctl_code": VID_IOCTL,
                "device_type": 0x22,
                "function": 0x15,
                "method": 0,
                "access": 0,
                "handler_name": "VidIoControlDriver",
                "handler_rva": "0x31ea8",
                "registration_rva": "0x60314",
                "dispatch_resolved": True,
                "unresolved_edges": [],
                "registration_evidence": {
                    "major_function_index": 14,
                    "driver_entry_rva": "0xc903c",
                    "device_add_rva": "0x5ffb0",
                    "preprocess_rva": "0x2e600",
                    "dispatch_rva": "0x31ea8",
                    "device_add_ref": ref(device_add_ptr),
                    "driver_create_ref": ref(driver_create),
                    "preprocess_target_ref": ref(preprocess_ptr),
                    "registration_ref": ref(registration),
                    "preprocess_call_ref": ref(preprocess_call),
                    "driver_api_table_offset": 0x3A0,
                    "registration_api_table_offset": 0x248,
                    "driver_config_argument_index": 4,
                    "callback_argument_index": 2,
                    "major_function_argument_index": 3,
                },
                "ioctl_match_evidence": {
                    "ioctl_code": VID_IOCTL,
                    "comparison_ref": ref(ioctl_compare),
                    "branch_ref": ref(ioctl_branch),
                    "target_ref": ref(ioctl_target),
                    "target_reaches_sink": True,
                    "entry_reachable": True,
                    "unique_sink_successor": True,
                    "dominates_handler": True,
                },
                "ops": raw_ops,
                "fields": [
                    {
                        "offset": 4,
                        "width": 4,
                        "kind": "length",
                        "source": "SystemBuffer",
                        "source_root": "irp.system_buffer",
                        "source_ref": ref(field_load),
                        "sink_kind": "copy",
                        "sink_function": "VidInformationIoctlGetSystemInformation",
                        "sink_address": "0xc5c78",
                        "sink_ref": ref(sink),
                        "sink_argument_index": 2,
                        "taint_path": [ref(field_load), ref(sink)],
                        "guard_evidence": [
                            {
                                "kind": "input-buffer-length",
                                "comparison_ref": ref(length_compare),
                                "branch_ref": ref(length_branch),
                                "checked_ref": ref(input_length),
                                "target_ref": ref(failure_status),
                                "target_reaches_sink": False,
                                "entry_reachable": True,
                                "unique_sink_successor": True,
                                "dominates_sink": True,
                            },
                            {
                                "kind": "field-within-input",
                                "comparison_ref": ref(bound_compare),
                                "branch_ref": ref(bound_branch),
                                "checked_ref": ref(field_load),
                                "target_ref": ref(failure_status),
                                "target_reaches_sink": False,
                                "entry_reachable": True,
                                "unique_sink_successor": True,
                                "dominates_sink": True,
                            },
                        ],
                    }
                ],
            }


def _finish_generic_acquisition(
    binary: Path,
    pdb: Path,
    image_base: int,
    architecture: str,
    pointer_size: int,
    direct: dict[str, Any],
    handler_name: str,
    handler_body: str,
    ioctl_values: set[int],
) -> dict[str, Any]:
    from .pe_symbols import pe_codeview_identity

    pe_identity = pe_codeview_identity(binary)
    if pe_identity is None:
        raise ValueError("live IOCTL extraction requires a PE CodeView identity")
    if len(ioctl_values) != 1:
        raise ValueError("live IOCTL extraction requires one exact constant IOCTL branch")
    ioctl_code = next(iter(ioctl_values))
    method = ioctl_code & 3
    if method == 3:
        raise ValueError("METHOD_NEITHER is rejected")
    if method != 0:
        raise ValueError("live IOCTL extraction accepts METHOD_BUFFERED only")
    if "SystemBuffer" not in handler_body:
        raise ValueError("typed WDM SystemBuffer root was not recovered")
    _require_no_unsupported_live_guard_sources(handler_body)
    type_material = cast(str, direct["type_material"])
    if not all(
        name in type_material for name in ("SystemBuffer", "InputBufferLength", "MajorFunction")
    ):
        raise ValueError("required PDB-backed WDM field types were not recovered")

    if direct["ioctl_code"] != ioctl_code:
        raise ValueError("typed body and raw High-P-Code IOCTL constants disagree")
    direct_length_dereferences = re.findall(
        r"\*\s*\(\s*(?:u?int|ulong|dword)[^)]*\*\s*\)[^,;\n]*SystemBuffer",
        handler_body,
        re.IGNORECASE,
    )
    if len(direct_length_dereferences) != 1:
        raise ValueError("one direct typed SystemBuffer length dereference was not recovered")
    offset = cast(int, direct["field_offset"])
    return {
        "schema_version": RAW_FACT_VERSION,
        "driver_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "pdb_sha256": hashlib.sha256(pdb.read_bytes()).hexdigest(),
        "pdb_codeview_identity": f"{pe_identity[0]}:{pe_identity[1]}:{pe_identity[2]}",
        "architecture": architecture,
        "pointer_size": pointer_size,
        "image_base": f"0x{image_base:x}",
        "coverage": {
            "framework": "wdm",
            "truncated": False,
            "dynamic_dispatch": False,
            "unresolved_edges": [],
        },
        "dispatches": [
            {
                "ioctl_code": ioctl_code,
                "device_type": ioctl_code >> 16,
                "function": (ioctl_code >> 2) & 0xFFF,
                "method": method,
                "access": (ioctl_code >> 14) & 3,
                "handler_name": handler_name,
                "handler_rva": direct["handler_rva"],
                "registration_rva": direct["registration_rva"],
                "dispatch_resolved": True,
                "unresolved_edges": [],
                "registration_evidence": {
                    "major_function_index": 14,
                    "target_rva": direct["handler_rva"],
                    "store_ref": direct["store_ref"],
                    "address_dependency_refs": direct["registration_address_refs"],
                    "target_dependency_refs": direct["registration_target_refs"],
                },
                "ioctl_match_evidence": {
                    "ioctl_code": ioctl_code,
                    "comparison_ref": direct["ioctl_compare_ref"],
                    "branch_ref": direct["ioctl_branch_ref"],
                    "dominates_handler": direct["ioctl_dominates_sink"],
                    "match_successor_ref": direct["ioctl_match_successor_ref"],
                    "reject_return_ref": direct["ioctl_reject_return_ref"],
                    "match_comparison_result": direct["ioctl_match_comparison_result"],
                    "entry_reachable": True,
                    "unique_match_successor": True,
                    "reject_successor_reaches_sink": False,
                },
                "ops": direct["ops"],
                "fields": [
                    {
                        "offset": offset,
                        "width": 4,
                        "kind": "length",
                        "source": "SystemBuffer",
                        "source_root": "irp.system_buffer",
                        "source_ref": direct["length_ref"],
                        "sink_kind": "copy",
                        "sink_function": direct["sink_function"],
                        "sink_address": direct["sink_rva"],
                        "sink_ref": direct["sink_ref"],
                        "sink_argument_index": 2,
                        "taint_path": direct["taint_path"],
                        "safety_proofs": direct["safety_proofs"],
                    }
                ],
            }
        ],
    }


def compile_windows_ioctl_high_pcode_facts(raw: dict[str, Any]) -> dict[str, Any]:
    """Validate semantic copy-span facts and return deterministic export v3."""
    return _compile_windows_ioctl_high_pcode_facts(
        raw, EXTRACTOR_PROFILE, EXTRACTOR_CONFIG_SHA256
    )


def _compile_windows_ioctl_high_pcode_facts(
    raw: dict[str, Any], profile: str, config_sha256: str
) -> dict[str, Any]:
    """Compile one internally selected, provenance-separated extractor profile."""
    if profile == VID_EXTRACTOR_PROFILE:
        if config_sha256 != VID_EXTRACTOR_CONFIG_SHA256:
            raise ValueError("Vid extractor config mismatch")
        _validate_vid_normalized_facts(raw)
    elif profile not in {EXTRACTOR_PROFILE, EXTRACTOR_PROFILE_V2} or config_sha256 != {
        EXTRACTOR_PROFILE: EXTRACTOR_CONFIG_SHA256,
        EXTRACTOR_PROFILE_V2: EXTRACTOR_CONFIG_SHA256_V2,
    }[profile]:
        raise ValueError("unsupported compiler extractor profile")
    _exact(
        raw,
        {
            "schema_version",
            "driver_sha256",
            "pdb_sha256",
            "pdb_codeview_identity",
            "architecture",
            "pointer_size",
            "image_base",
            "coverage",
            "dispatches",
        },
        "fact graph",
    )
    semantic_proofs = profile == EXTRACTOR_PROFILE
    expected_raw_version = RAW_FACT_VERSION_V2 if semantic_proofs else RAW_FACT_VERSION_V1
    if raw["schema_version"] != expected_raw_version:
        raise ValueError("unsupported normalized High-P-Code fact graph")
    driver = _sha(raw["driver_sha256"], "driver_sha256")
    pdb = _sha(raw["pdb_sha256"], "pdb_sha256")
    codeview = _text(raw["pdb_codeview_identity"], "pdb_codeview_identity", 512)
    arch = _enum(raw["architecture"], _ARCHES, "architecture")
    pointer_size = _integer(raw["pointer_size"], "pointer_size", 4, 8)
    if (arch == "x86" and pointer_size != 4) or (arch != "x86" and pointer_size != 8):
        raise ValueError("architecture and pointer size mismatch")
    image_base = _rva(raw["image_base"], "image_base", allow_zero=False)
    is_vid_profile = profile == VID_EXTRACTOR_PROFILE
    coverage = _coverage(raw["coverage"], allow_vid=is_vid_profile)
    dispatches_raw = raw["dispatches"]
    if not isinstance(dispatches_raw, list) or not 1 <= len(dispatches_raw) <= 128:
        raise ValueError("fact graph dispatches must be a bounded nonempty array")
    dispatches = [
        _dispatch(
            value,
            image_base,
            allow_vid=is_vid_profile,
            semantic_proofs=semantic_proofs,
        )
        for value in dispatches_raw
    ]
    dispatches.sort(key=lambda row: (cast(int, row["ioctl_code"]), str(row["handler_rva"])))
    if len({cast(int, row["ioctl_code"]) for row in dispatches}) != len(dispatches):
        raise ValueError("duplicate IOCTL dispatch")
    facts = {
        "schema_version": expected_raw_version,
        "architecture": arch,
        "pointer_size": pointer_size,
        "image_base": image_base,
        "coverage": coverage,
        "dispatches": dispatches,
    }
    return {
        "schema_version": EXPORT_VERSION_V3 if semantic_proofs else EXPORT_VERSION_V2,
        "producer": "ghidra-high-pcode",
        "extractor_profile": profile,
        "extractor_config_sha256": config_sha256,
        "driver_sha256": driver,
        "pdb_sha256": pdb,
        "pdb_codeview_identity": codeview,
        "facts": facts,
        "dispatches": [_legacy_dispatch(row) for row in dispatches],
        "static_only": True,
        "device_ioctl_attempts": 0,
        "execution_authorized": False,
    }


def _validate_vid_normalized_facts(raw: dict[str, Any]) -> None:
    """Pin every retained semantic needed to identify the reviewed Vid slice."""
    if (
        raw.get("driver_sha256") != VID_DRIVER_SHA256
        or raw.get("pdb_sha256") != VID_PDB_SHA256
        or raw.get("pdb_codeview_identity") != VID_CODEVIEW
        or raw.get("architecture") != "x86_64"
        or raw.get("pointer_size") != 8
        or raw.get("image_base") != "0x140000000"
    ):
        raise ValueError("Vid extractor profile artifact identity mismatch")
    expected_coverage = {
        "framework": "kmdf-wdm-preprocess",
        "scope": {"kind": "ioctl-allowlist", "ioctl_codes": [VID_IOCTL], "exhaustive": True},
        "truncated": False,
        "dynamic_dispatch": False,
        "unresolved_edges": [],
    }
    if raw.get("coverage") != expected_coverage:
        raise ValueError("Vid extractor profile coverage mismatch")
    dispatches = raw.get("dispatches")
    if not isinstance(dispatches, list) or len(dispatches) != 1:
        raise ValueError("Vid extractor profile requires one dispatch")
    dispatch = _object(dispatches[0], "Vid dispatch")
    expected = {
        "ioctl_code": VID_IOCTL,
        "device_type": 0x22,
        "function": 0x15,
        "method": 0,
        "access": 0,
        "handler_name": "VidIoControlDriver",
        "handler_rva": "0x31ea8",
        "registration_rva": "0x60314",
        "dispatch_resolved": True,
        "unresolved_edges": [],
    }
    if any(dispatch.get(name) != value for name, value in expected.items()):
        raise ValueError("Vid extractor profile dispatch mismatch")
    fields = dispatch.get("fields")
    if not isinstance(fields, list) or len(fields) != 1:
        raise ValueError("Vid extractor profile requires one field flow")
    field = _object(fields[0], "Vid field")
    if any(
        field.get(name) != value
        for name, value in {
            "offset": 4,
            "width": 4,
            "kind": "length",
            "source": "SystemBuffer",
            "source_root": "irp.system_buffer",
            "sink_kind": "copy",
            "sink_function": "VidInformationIoctlGetSystemInformation",
            "sink_address": "0xc5c78",
            "sink_argument_index": 2,
        }.items()
    ):
        raise ValueError("Vid extractor profile field-to-sink mismatch")
    guards = field.get("guard_evidence")
    guard_kinds = (
        {item.get("kind") for item in guards if isinstance(item, dict)}
        if isinstance(guards, list)
        else set()
    )
    if guard_kinds != {
        "input-buffer-length",
        "field-within-input",
    }:
        raise ValueError("Vid extractor profile guard coverage mismatch")

    def expected_ref(
        function_rva: int, instruction_rva: int, order: int, opcode: str
    ) -> dict[str, object]:
        return {
            "function_rva": f"0x{function_rva:x}",
            "instruction_rva": f"0x{instruction_rva:x}",
            "pcode_order": order,
            "opcode": opcode,
        }

    specs = [
        ("device_add", 0xC903C, 0xC90E8, 119, "PTRSUB", ()),
        ("driver_config", 0xC903C, 0xC916B, 1218, "PTRSUB", ()),
        ("driver_api_add", 0xC903C, 0xC918A, 196, "INT_ADD", ()),
        ("driver_api_cast", 0xC903C, 0xC918A, 1225, "CAST", ("driver_api_add",)),
        ("driver_api_load", 0xC903C, 0xC918A, 197, "LOAD", ("driver_api_cast",)),
        (
            "driver_create",
            0xC903C,
            0xC9191,
            314,
            "CALLIND",
            ("driver_config", "driver_api_load"),
        ),
        ("preprocess_target", 0x5FFB0, 0x60314, 4910, "PTRSUB", ()),
        ("registration_api_add", 0x5FFB0, 0x602F4, 567, "INT_ADD", ()),
        (
            "registration_api_cast",
            0x5FFB0,
            0x602F4,
            4971,
            "CAST",
            ("registration_api_add",),
        ),
        (
            "registration_api_load",
            0x5FFB0,
            0x602F4,
            568,
            "LOAD",
            ("registration_api_cast",),
        ),
        (
            "registration",
            0x5FFB0,
            0x60314,
            1076,
            "CALLIND",
            ("registration_api_load", "preprocess_target"),
        ),
        ("preprocess_call", 0x2E600, 0x2E92F, 892, "CALL", ()),
        ("ioctl_compare", 0x31EA8, 0x3213E, 693, "INT_EQUAL", ()),
        ("ioctl_branch", 0x31EA8, 0x32140, 698, "CBRANCH", ("ioctl_compare",)),
        ("ioctl_target", 0x31EA8, 0x32176, 754, "COPY", ()),
        ("input_length", 0x31EA8, 0x31ED7, 3499, "SUBPIECE", ()),
        ("length_compare", 0x31EA8, 0x3217A, 765, "INT_LESS", ("input_length",)),
        ("length_branch", 0x31EA8, 0x3217E, 774, "CBRANCH", ("length_compare",)),
        ("buffer_cast", 0x31EA8, 0x32184, 5037, "CAST", ()),
        ("field_address", 0x31EA8, 0x32184, 775, "INT_ADD", ("buffer_cast",)),
        ("field_cast", 0x31EA8, 0x32184, 5038, "CAST", ("field_address",)),
        ("field_load", 0x31EA8, 0x32184, 776, "LOAD", ("field_cast",)),
        ("bound_sub", 0x31EA8, 0x32188, 779, "INT_SUB", ("input_length",)),
        (
            "bound_compare",
            0x31EA8,
            0x3218C,
            783,
            "INT_LESSEQUAL",
            ("field_load", "bound_sub"),
        ),
        ("bound_branch", 0x31EA8, 0x3218F, 792, "CBRANCH", ("bound_compare",)),
        ("sink", 0x31EA8, 0x321B0, 815, "CALL", ("field_load",)),
        ("failure_status", 0x31EA8, 0x325AC, 212, "COPY", ()),
        ("failure_return", 0x31EA8, 0x325B3, 228, "RETURN", ("failure_status",)),
    ]
    refs = {
        name: expected_ref(function_rva, instruction_rva, order, opcode)
        for name, function_rva, instruction_rva, order, opcode, _inputs in specs
    }
    expected_graph = {
        _ref_token(refs[name]): {_ref_token(refs[input_name]) for input_name in inputs}
        for name, _function_rva, _instruction_rva, _order, _opcode, inputs in specs
    }
    ops = dispatch.get("ops")
    if not isinstance(ops, list) or len(ops) != len(specs):
        raise ValueError("Vid extractor profile operation set mismatch")
    actual_graph: dict[str, set[str]] = {}
    for item in ops:
        operation = _object(item, "Vid operation")
        _exact(operation, {"ref", "input_refs"}, "Vid operation")
        operation_ref = _ref(operation["ref"])
        input_refs = operation["input_refs"]
        if not isinstance(input_refs, list):
            raise ValueError("Vid extractor profile operation inputs mismatch")
        token = _ref_token(operation_ref)
        if token in actual_graph:
            raise ValueError("Vid extractor profile operation set mismatch")
        actual_graph[token] = {_ref_token(_ref(item)) for item in input_refs}
    if actual_graph != expected_graph:
        raise ValueError("Vid extractor profile operation graph mismatch")

    registration = _object(dispatch.get("registration_evidence"), "Vid registration")
    expected_registration_refs = {
        "device_add_ref": refs["device_add"],
        "driver_create_ref": refs["driver_create"],
        "preprocess_target_ref": refs["preprocess_target"],
        "registration_ref": refs["registration"],
        "preprocess_call_ref": refs["preprocess_call"],
    }
    if any(registration.get(name) != value for name, value in expected_registration_refs.items()):
        raise ValueError("Vid extractor profile registration references mismatch")
    ioctl_match = _object(dispatch.get("ioctl_match_evidence"), "Vid IOCTL match")
    if (
        ioctl_match.get("comparison_ref") != refs["ioctl_compare"]
        or ioctl_match.get("branch_ref") != refs["ioctl_branch"]
        or ioctl_match.get("target_ref") != refs["ioctl_target"]
        or ioctl_match.get("target_reaches_sink") is not True
        or ioctl_match.get("entry_reachable") is not True
        or ioctl_match.get("unique_sink_successor") is not True
        or ioctl_match.get("dominates_handler") is not True
    ):
        raise ValueError("Vid extractor profile IOCTL proof mismatch")
    if (
        field.get("source_ref") != refs["field_load"]
        or field.get("sink_ref") != refs["sink"]
        or field.get("taint_path") != [refs["field_load"], refs["sink"]]
    ):
        raise ValueError("Vid extractor profile field dependency mismatch")
    expected_guards = {
        "input-buffer-length": (
            refs["length_compare"],
            refs["length_branch"],
            refs["input_length"],
        ),
        "field-within-input": (
            refs["bound_compare"],
            refs["bound_branch"],
            refs["field_load"],
        ),
    }
    for item in cast(list[object], guards):
        guard = _object(item, "Vid guard")
        expected_guard = expected_guards.get(cast(str, guard.get("kind")))
        if expected_guard is None or (
            guard.get("comparison_ref"),
            guard.get("branch_ref"),
            guard.get("checked_ref"),
        ) != expected_guard or (
            guard.get("target_ref") != refs["failure_status"]
            or guard.get("target_reaches_sink") is not False
            or guard.get("entry_reachable") is not True
            or guard.get("unique_sink_successor") is not True
            or guard.get("dominates_sink") is not True
        ):
            raise ValueError("Vid extractor profile guard proof mismatch")


def validate_windows_ioctl_high_pcode_export(raw: dict[str, Any]) -> None:
    """Revalidate an immutable v2 or semantic-proof v3 export by round trip."""
    _exact(
        raw,
        {
            "schema_version",
            "producer",
            "extractor_profile",
            "extractor_config_sha256",
            "driver_sha256",
            "pdb_sha256",
            "pdb_codeview_identity",
            "facts",
            "dispatches",
            "static_only",
            "device_ioctl_attempts",
            "execution_authorized",
        },
        "High-P-Code export",
    )
    profile = raw["extractor_profile"]
    expected_config = {
        EXTRACTOR_PROFILE: EXTRACTOR_CONFIG_SHA256,
        EXTRACTOR_PROFILE_V2: EXTRACTOR_CONFIG_SHA256_V2,
        VID_EXTRACTOR_PROFILE: VID_EXTRACTOR_CONFIG_SHA256,
    }.get(profile)
    schema = raw["schema_version"]
    semantic_proofs = schema == EXPORT_VERSION_V3
    valid_pair = (schema, profile) in {
        (EXPORT_VERSION_V3, EXTRACTOR_PROFILE),
        (EXPORT_VERSION_V2, EXTRACTOR_PROFILE_V2),
        (EXPORT_VERSION_V2, VID_EXTRACTOR_PROFILE),
    }
    if (
        raw["producer"] != "ghidra-high-pcode"
        or not valid_pair
        or expected_config is None
        or raw["extractor_config_sha256"] != expected_config
        or raw["static_only"] is not True
        or raw["device_ioctl_attempts"] != 0
        or raw["execution_authorized"] is not False
    ):
        raise ValueError("unsupported Windows IOCTL High-P-Code export")
    facts = _object(raw["facts"], "High-P-Code facts")
    _exact(
        facts,
        {"schema_version", "architecture", "pointer_size", "image_base", "coverage", "dispatches"},
        "High-P-Code facts",
    )
    normalized = {
        "schema_version": RAW_FACT_VERSION_V2 if semantic_proofs else RAW_FACT_VERSION_V1,
        **{name: raw[name] for name in ("driver_sha256", "pdb_sha256", "pdb_codeview_identity")},
        **{
            name: facts[name] for name in ("architecture", "pointer_size", "image_base", "coverage")
        },
        "dispatches": [
            _raw_dispatch(
                _object(item, "rich dispatch"), semantic_proofs=semantic_proofs
            )
            for item in _list(facts["dispatches"], "rich dispatches")
        ],
    }
    if profile == VID_EXTRACTOR_PROFILE:
        _validate_vid_normalized_facts(normalized)
        rebuilt = _compile_windows_ioctl_high_pcode_facts(
            normalized, VID_EXTRACTOR_PROFILE, VID_EXTRACTOR_CONFIG_SHA256
        )
    elif profile == EXTRACTOR_PROFILE:
        rebuilt = compile_windows_ioctl_high_pcode_facts(normalized)
    else:
        rebuilt = _compile_windows_ioctl_high_pcode_facts(
            normalized, EXTRACTOR_PROFILE_V2, EXTRACTOR_CONFIG_SHA256_V2
        )
    if rebuilt != raw:
        raise ValueError("Windows IOCTL High-P-Code export is not canonical")


def canonical_export_bytes(raw: dict[str, Any]) -> bytes:
    """Return the sole canonical retained encoding after full validation."""
    validate_windows_ioctl_high_pcode_export(raw)
    return (
        json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()


def _coverage(raw: object, *, allow_vid: bool = False) -> dict[str, object]:
    value = _object(raw, "coverage")
    if allow_vid and set(value) == {
        "framework",
        "scope",
        "truncated",
        "dynamic_dispatch",
        "unresolved_edges",
    }:
        scope = _object(value["scope"], "coverage scope")
        _exact(scope, {"kind", "ioctl_codes", "exhaustive"}, "coverage scope")
        if (
            value["framework"] != "kmdf-wdm-preprocess"
            or scope != {
                "kind": "ioctl-allowlist",
                "ioctl_codes": [VID_IOCTL],
                "exhaustive": True,
            }
        ):
            raise ValueError("unsupported KMDF-to-WDM coverage scope")
        if value["truncated"] is not False or value["dynamic_dispatch"] is not False:
            raise ValueError("truncated or dynamic dispatch evidence is rejected")
        if value["unresolved_edges"] != []:
            raise ValueError("unresolved High-P-Code edges are rejected")
        return {
            "framework": "kmdf-wdm-preprocess",
            "scope": dict(scope),
            "truncated": False,
            "dynamic_dispatch": False,
            "unresolved_edges": [],
        }
    _exact(value, {"framework", "truncated", "dynamic_dispatch", "unresolved_edges"}, "coverage")
    if value["framework"] != "wdm":
        raise ValueError("KMDF and non-WDM fact graphs are unsupported")
    if value["truncated"] is not False or value["dynamic_dispatch"] is not False:
        raise ValueError("truncated or dynamic dispatch evidence is rejected")
    if value["unresolved_edges"] != []:
        raise ValueError("unresolved High-P-Code edges are rejected")
    return {
        "framework": "wdm",
        "truncated": False,
        "dynamic_dispatch": False,
        "unresolved_edges": [],
    }


def _dispatch(
    raw: object,
    image_base: str,
    *,
    allow_vid: bool = False,
    semantic_proofs: bool = False,
) -> dict[str, object]:
    value = _object(raw, "dispatch")
    _exact(
        value,
        {
            "ioctl_code",
            "device_type",
            "function",
            "method",
            "access",
            "handler_name",
            "handler_rva",
            "registration_rva",
            "dispatch_resolved",
            "unresolved_edges",
            "registration_evidence",
            "ioctl_match_evidence",
            "ops",
            "fields",
        },
        "dispatch",
    )
    code = _integer(value["ioctl_code"], "ioctl_code", 0, 0xFFFFFFFF)
    device_type = _integer(value["device_type"], "device_type", 0, 0xFFFF)
    function = _integer(value["function"], "function", 0, 0xFFF)
    method = _integer(value["method"], "method", 0, 3)
    access = _integer(value["access"], "access", 0, 3)
    if method == 3:
        raise ValueError("METHOD_NEITHER is rejected")
    if method != 0:
        raise ValueError("v2 accepts METHOD_BUFFERED only")
    if code != (device_type << 16) | (access << 14) | (function << 2) | method:
        raise ValueError("IOCTL CTL_CODE decomposition mismatch")
    if value["dispatch_resolved"] is not True or value["unresolved_edges"] != []:
        raise ValueError("unresolved or dynamic dispatch is rejected")
    handler_rva = _rva(value["handler_rva"], "handler_rva")
    registration_rva = _rva(value["registration_rva"], "registration_rva")
    ops_raw = value["ops"]
    if not isinstance(ops_raw, list) or not 1 <= len(ops_raw) <= 16384:
        raise ValueError("dispatch ops must be a bounded nonempty array")
    ops = [_op(item, allow_vid=allow_vid) for item in ops_raw]
    ops.sort(key=lambda item: _ref_key(_object(item["ref"], "op ref")))
    op_index = {_ref_token(_object(item["ref"], "op ref")): item for item in ops}
    if len(op_index) != len(ops):
        raise ValueError("duplicate stable High-P-Code op reference")
    registration = _registration(
        value["registration_evidence"], op_index, handler_rva, allow_vid=allow_vid
    )
    match = _ioctl_match(
        value["ioctl_match_evidence"],
        op_index,
        code,
        allow_vid=allow_vid,
        semantic_proofs=semantic_proofs,
    )
    fields_raw = value["fields"]
    if not isinstance(fields_raw, list) or not 1 <= len(fields_raw) <= 64:
        raise ValueError("dispatch fields must be a bounded nonempty array")
    fields = [
        _field(
            item,
            op_index,
            allow_vid=allow_vid,
            semantic_proofs=semantic_proofs,
        )
        for item in fields_raw
    ]
    fields.sort(
        key=lambda item: (
            cast(int, item["offset"]),
            cast(int, item["width"]),
            str(item["kind"]),
            cast(int, item["source_inst_id"]),
            cast(int, item["sink_inst_id"]),
        )
    )
    identities = [
        (item["offset"], item["width"], item["kind"], item["source_inst_id"], item["sink_inst_id"])
        for item in fields
    ]
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate field evidence")
    return {
        "ioctl_code": code,
        "device_type": device_type,
        "function": function,
        "method": method,
        "access": access,
        "handler_name": _text(value["handler_name"], "handler_name", 256),
        "handler_rva": handler_rva,
        "registration_rva": registration_rva,
        "dispatch_resolved": True,
        "unresolved_edges": [],
        "registration_evidence": registration,
        "ioctl_match_evidence": match,
        "ops": ops,
        "fields": fields,
        "image_base": image_base,
    }


def _legacy_dispatch(raw: dict[str, object]) -> dict[str, object]:
    """Derive, never trust, the exact dispatch summary consumed by rank v1."""
    fields_raw = raw["fields"]
    assert isinstance(fields_raw, list)
    fields: list[dict[str, object]] = []
    for item in fields_raw:
        field = _object(item, "rich field")
        fields.append(
            {
                "offset": field["offset"],
                "width": field["width"],
                "kind": field["kind"],
                "source": field["source"],
                "source_inst_id": field["source_inst_id"],
                "sink_kind": field["sink_kind"],
                "sink_function": field["sink_function"],
                "sink_address": field["sink_address"],
                "sink_inst_id": field["sink_inst_id"],
                "guards": field["guards"],
            }
        )
    return {
        "ioctl_code": raw["ioctl_code"],
        "device_type": raw["device_type"],
        "function": raw["function"],
        "method": raw["method"],
        "access": raw["access"],
        "handler_name": raw["handler_name"],
        "handler_rva": raw["handler_rva"],
        "registration_rva": raw["registration_rva"],
        "dispatch_resolved": True,
        "unresolved_edges": [],
        "fields": fields,
    }


def _raw_dispatch(raw: dict[str, Any], *, semantic_proofs: bool = False) -> dict[str, object]:
    """Recover the compiler input solely to revalidate a retained rich graph."""
    ops = []
    for item in _list(raw["ops"], "rich ops"):
        op = _object(item, "rich op")
        _exact(op, {"ref", "input_refs", "stable_id"}, "rich op")
        if op["stable_id"] != _stable_op_id(_object(op["ref"], "op ref")):
            raise ValueError("rich op stable_id mismatch")
        ops.append({"ref": op["ref"], "input_refs": op["input_refs"]})
    fields = []
    for item in _list(raw["fields"], "rich fields"):
        field = _object(item, "rich field")
        source_evidence = _object(field["source_evidence"], "source evidence")
        sink_evidence = _object(field["sink_evidence"], "sink evidence")
        proof_projection: dict[str, object]
        if semantic_proofs:
            proofs = []
            for proof_item in _list(field["safety_proofs"], "safety proofs"):
                proof = _object(proof_item, "rich safety proof")
                proofs.append(
                    {
                        name: proof[name]
                        for name in proof
                        if name not in {"sink_ref"}
                    }
                )
            proof_projection = {"safety_proofs": proofs}
        else:
            guards = []
            for guard_item in _list(field["guard_evidence"], "guard evidence"):
                guard = _object(guard_item, "rich guard")
                names = [
                    "kind",
                    "comparison_ref",
                    "branch_ref",
                    "dominates_sink",
                    "checked_ref",
                ]
                names.extend(
                    name
                    for name in (
                        "target_ref",
                        "target_reaches_sink",
                        "entry_reachable",
                        "unique_sink_successor",
                    )
                    if name in guard
                )
                guards.append({name: guard[name] for name in names})
            proof_projection = {"guard_evidence": guards}
        fields.append(
            {
                "offset": field["offset"],
                "width": field["width"],
                "kind": field["kind"],
                "source": field["source"],
                "source_root": source_evidence["root"],
                "source_ref": source_evidence["ref"],
                "sink_kind": field["sink_kind"],
                "sink_function": field["sink_function"],
                "sink_address": field["sink_address"],
                "sink_ref": sink_evidence["ref"],
                "sink_argument_index": field["sink_argument_index"],
                "taint_path": field["taint_path"],
                **proof_projection,
            }
        )
    return {
        **{
            name: raw[name]
            for name in (
                "ioctl_code",
                "device_type",
                "function",
                "method",
                "access",
                "handler_name",
                "handler_rva",
                "registration_rva",
                "dispatch_resolved",
                "unresolved_edges",
                "registration_evidence",
                "ioctl_match_evidence",
            )
        },
        "ops": ops,
        "fields": fields,
    }


def _op(raw: object, *, allow_vid: bool = False) -> dict[str, object]:
    value = _object(raw, "op")
    _exact(value, {"ref", "input_refs"}, "op")
    ref = _ref(value["ref"])
    if not allow_vid and ref["opcode"] not in _OPCODES:
        raise ValueError("opcode is unsupported by the generic WDM profile")
    inputs_raw = value["input_refs"]
    if not isinstance(inputs_raw, list) or len(inputs_raw) > 32:
        raise ValueError("op input_refs must be a bounded array")
    inputs = [_ref(item) for item in inputs_raw]
    if [_ref_key(item) for item in inputs] != sorted({_ref_key(item) for item in inputs}):
        raise ValueError("op input_refs must be sorted and unique")
    return {"ref": ref, "input_refs": inputs, "stable_id": _stable_op_id(ref)}


def _registration(
    raw: object,
    ops: dict[str, dict[str, object]],
    handler_rva: str,
    *,
    allow_vid: bool = False,
) -> dict[str, object]:
    value = _object(raw, "registration evidence")
    vid_fields = {
        "major_function_index",
        "driver_entry_rva",
        "device_add_rva",
        "preprocess_rva",
        "dispatch_rva",
        "device_add_ref",
        "driver_create_ref",
        "preprocess_target_ref",
        "registration_ref",
        "preprocess_call_ref",
        "driver_api_table_offset",
        "registration_api_table_offset",
        "driver_config_argument_index",
        "callback_argument_index",
        "major_function_argument_index",
    }
    if allow_vid and set(value) == vid_fields:
        if value["major_function_index"] != 14:
            raise ValueError("IRP_MJ_DEVICE_CONTROL registration binding mismatch")
        rvas = {
            name: _rva(value[name], name)
            for name in ("driver_entry_rva", "device_add_rva", "preprocess_rva", "dispatch_rva")
        }
        if rvas != {
            "driver_entry_rva": "0xc903c",
            "device_add_rva": "0x5ffb0",
            "preprocess_rva": "0x2e600",
            "dispatch_rva": handler_rva,
        }:
            raise ValueError("KMDF-to-WDM registration chain mismatch")
        scalar = {
            "driver_api_table_offset": 0x3A0,
            "registration_api_table_offset": 0x248,
            "driver_config_argument_index": 4,
            "callback_argument_index": 2,
            "major_function_argument_index": 3,
        }
        if any(value[name] != expected for name, expected in scalar.items()):
            raise ValueError("KMDF-to-WDM positional registration binding mismatch")
        references = {
            name: _known_ref(value[name], ops, name)
            for name in (
                "device_add_ref",
                "driver_create_ref",
                "preprocess_target_ref",
                "registration_ref",
                "preprocess_call_ref",
            )
        }
        expected_opcodes = {
            "device_add_ref": "PTRSUB",
            "driver_create_ref": "CALLIND",
            "preprocess_target_ref": "PTRSUB",
            "registration_ref": "CALLIND",
            "preprocess_call_ref": "CALL",
        }
        if any(references[name]["opcode"] != opcode for name, opcode in expected_opcodes.items()):
            raise ValueError("KMDF-to-WDM registration evidence opcode mismatch")
        return {"major_function_index": 14, **rvas, **references, **scalar}
    _exact(
        value,
        {
            "major_function_index",
            "target_rva",
            "store_ref",
            "address_dependency_refs",
            "target_dependency_refs",
        },
        "registration evidence",
    )
    if (
        value["major_function_index"] != 14
        or _rva(value["target_rva"], "target_rva") != handler_rva
    ):
        raise ValueError("WDM IRP_MJ_DEVICE_CONTROL registration binding mismatch")
    store = _known_ref(value["store_ref"], ops, "registration store")
    if store["opcode"] != "STORE":
        raise ValueError("WDM registration evidence must reference STORE")
    address_refs = _known_ref_array(
        value["address_dependency_refs"], ops, "registration address dependencies"
    )
    target_refs = _known_ref_array(
        value["target_dependency_refs"], ops, "registration target dependencies"
    )
    if not address_refs or not target_refs:
        raise ValueError("WDM registration dependency evidence is incomplete")
    store_inputs = _op_input_tokens(ops, store)
    roots = {_ref_token(address_refs[-1]), _ref_token(target_refs[-1])}
    if not roots <= store_inputs:
        raise ValueError("WDM registration STORE is not bound to its address and target")
    _require_continuous_dependency_path(address_refs, ops, "registration address")
    _require_continuous_dependency_path(target_refs, ops, "registration target")
    return {
        "major_function_index": 14,
        "target_rva": handler_rva,
        "store_ref": store,
        "address_dependency_refs": address_refs,
        "target_dependency_refs": target_refs,
    }


def _ioctl_match(
    raw: object,
    ops: dict[str, dict[str, object]],
    code: int,
    *,
    allow_vid: bool = False,
    semantic_proofs: bool = False,
) -> dict[str, object]:
    value = _object(raw, "IOCTL match evidence")
    fields = {"ioctl_code", "comparison_ref", "branch_ref", "dominates_handler"}
    if allow_vid:
        fields |= {
            "target_ref",
            "target_reaches_sink",
            "entry_reachable",
            "unique_sink_successor",
        }
    if semantic_proofs:
        fields |= {
            "match_successor_ref",
            "reject_return_ref",
            "match_comparison_result",
            "entry_reachable",
            "unique_match_successor",
            "reject_successor_reaches_sink",
        }
    _exact(
        value,
        fields,
        "IOCTL match evidence",
    )
    if value["ioctl_code"] != code or value["dominates_handler"] is not True:
        raise ValueError("IOCTL branch does not dominate the selected handler")
    comparison = _known_ref(value["comparison_ref"], ops, "IOCTL comparison")
    branch = _known_ref(value["branch_ref"], ops, "IOCTL branch")
    if comparison["opcode"] not in {"INT_EQUAL", "INT_NOTEQUAL"} or branch["opcode"] != "CBRANCH":
        raise ValueError("IOCTL match evidence opcodes are invalid")
    if _ref_token(comparison) not in _op_input_tokens(ops, branch):
        raise ValueError("IOCTL CBRANCH does not consume its comparison")
    result = {
        "ioctl_code": code,
        "comparison_ref": comparison,
        "branch_ref": branch,
        "dominates_handler": True,
    }
    if semantic_proofs:
        match_successor = _known_ref(
            value["match_successor_ref"], ops, "IOCTL match successor"
        )
        reject_return = _known_ref(
            value["reject_return_ref"], ops, "IOCTL reject RETURN"
        )
        expected_result = comparison["opcode"] == "INT_EQUAL"
        if (
            value["match_comparison_result"] is not expected_result
            or value["entry_reachable"] is not True
            or value["unique_match_successor"] is not True
            or value["reject_successor_reaches_sink"] is not False
            or reject_return["opcode"] != "RETURN"
        ):
            raise ValueError("IOCTL semantic branch polarity proof mismatch")
        result.update(
            {
                "match_successor_ref": match_successor,
                "reject_return_ref": reject_return,
                "match_comparison_result": expected_result,
                "entry_reachable": True,
                "unique_match_successor": True,
                "reject_successor_reaches_sink": False,
            }
        )
    if allow_vid:
        target = _known_ref(value["target_ref"], ops, "IOCTL branch target")
        if (
            target["opcode"] != "COPY"
            or value["target_reaches_sink"] is not True
            or value["entry_reachable"] is not True
            or value["unique_sink_successor"] is not True
        ):
            raise ValueError("Vid IOCTL CFG proof mismatch")
        result.update(
            {
                "target_ref": target,
                "target_reaches_sink": True,
                "entry_reachable": True,
                "unique_sink_successor": True,
            }
        )
    return result


def _field(
    raw: object,
    ops: dict[str, dict[str, object]],
    *,
    allow_vid: bool = False,
    semantic_proofs: bool = False,
) -> dict[str, object]:
    value = _object(raw, "field")
    proof_field = "safety_proofs" if semantic_proofs else "guard_evidence"
    _exact(
        value,
        {
            "offset",
            "width",
            "kind",
            "source",
            "source_root",
            "source_ref",
            "sink_kind",
            "sink_function",
            "sink_address",
            "sink_ref",
            "sink_argument_index",
            "taint_path",
            proof_field,
        },
        "field",
    )
    source = _enum(value["source"], set(_SOURCES), "source")
    if value["source_root"] != _SOURCES[source]:
        raise ValueError("field source root mismatch")
    source_ref = _known_ref(value["source_ref"], ops, "field source")
    sink_ref = _known_ref(value["sink_ref"], ops, "field sink")
    sink_kind = _enum(value["sink_kind"], _SINKS, "sink_kind")
    if (sink_kind == "indexed-store" and sink_ref["opcode"] != "STORE") or (
        sink_kind != "indexed-store" and sink_ref["opcode"] != "CALL"
    ):
        raise ValueError("field sink opcode mismatch")
    argument = _integer(value["sink_argument_index"], "sink_argument_index", 0, 31)
    field_offset = _integer(value["offset"], "field offset", 0, 1 << 20)
    field_width = _integer(value["width"], "field width", 1, 8)
    field_kind = _enum(value["kind"], _FIELD_KINDS, "field kind")
    path_raw = value["taint_path"]
    if not isinstance(path_raw, list) or not 2 <= len(path_raw) <= 256:
        raise ValueError("taint path must be a bounded source-to-sink array")
    path = [_known_ref(item, ops, "taint path") for item in path_raw]
    tokens = [_ref_token(item) for item in path]
    if (
        tokens[0] != _ref_token(source_ref)
        or tokens[-1] != _ref_token(sink_ref)
        or len(tokens) != len(set(tokens))
    ):
        raise ValueError("taint path endpoints or uniqueness are invalid")
    for previous, current in pairwise(tokens):
        inputs = _list(ops[current]["input_refs"], "op input refs")
        if previous not in {_ref_token(_object(item, "input ref")) for item in inputs}:
            raise ValueError("taint path is not a continuous def-use chain")
    guards: list[dict[str, object]] = []
    proofs: list[dict[str, object]] = []
    if semantic_proofs:
        proofs_raw = value["safety_proofs"]
        if not isinstance(proofs_raw, list) or len(proofs_raw) > 3:
            raise ValueError("safety proofs must be a bounded array")
        proofs = [
            _safety_proof(item, ops, source_ref=source_ref, sink_ref=sink_ref)
            for item in proofs_raw
        ]
        proofs.sort(key=lambda item: str(item["proof_kind"]))
        proof_kinds = [str(item["proof_kind"]) for item in proofs]
        if len(proof_kinds) != len(set(proof_kinds)):
            raise ValueError("duplicate semantic safety proof kind")
        present = set(proof_kinds)
        by_kind = {str(item["proof_kind"]): item for item in proofs}
        for proof_kind in ("input-field-readable", "source-copy-span"):
            proof = by_kind.get(proof_kind)
            if proof is not None and proof["field_end"] != field_offset + field_width:
                raise ValueError("semantic proof field_end does not match field geometry")
        header = by_kind.get("input-field-readable")
        source_span = by_kind.get("source-copy-span")
        if (
            header is not None
            and source_span is not None
            and header["input_buffer_length_ref"] != source_span["input_buffer_length_ref"]
        ):
            raise ValueError("compound source-span proofs use different InputBufferLength loads")
        kinds: list[str] = []
        if "input-field-readable" in present:
            kinds.extend(("field-within-input", "input-buffer-length"))
        if {
            "input-field-readable",
            "source-copy-span",
            "destination-copy-span",
        } <= present:
            kinds.append("checked-arithmetic")
        kinds.sort()
    else:
        guards_raw = value["guard_evidence"]
        if not isinstance(guards_raw, list) or len(guards_raw) > len(_GUARDS):
            raise ValueError("guard evidence must be a bounded array")
        guards = [_guard(item, ops, sink_ref, allow_vid=allow_vid) for item in guards_raw]
        guards.sort(
            key=lambda item: (
                str(item["kind"]),
                _ref_key(_object(item["comparison_ref"], "guard comparison")),
            )
        )
        kinds = [str(item["kind"]) for item in guards]
        if len(kinds) != len(set(kinds)):
            raise ValueError("duplicate guard evidence kind")
    sink_function = _text(value["sink_function"], "sink_function", 256)
    if _NAME.fullmatch(sink_function) is None:
        raise ValueError("sink_function is invalid")
    result = {
        "offset": field_offset,
        "width": field_width,
        "kind": field_kind,
        "source": source,
        "source_inst_id": _stable_op_id(source_ref),
        "source_evidence": {"root": _SOURCES[source], "ref": source_ref},
        "sink_kind": sink_kind,
        "sink_function": sink_function,
        "sink_address": _rva(value["sink_address"], "sink_address"),
        "sink_inst_id": _stable_op_id(sink_ref),
        "sink_argument_index": argument,
        "sink_evidence": {"ref": sink_ref},
        "taint_path": path,
        "guards": kinds,
    }
    if semantic_proofs:
        result["safety_proofs"] = proofs
    else:
        result["guard_evidence"] = guards
    return result


def _guard(
    raw: object,
    ops: dict[str, dict[str, object]],
    sink_ref: dict[str, object],
    *,
    allow_vid: bool = False,
) -> dict[str, object]:
    value = _object(raw, "guard evidence")
    fields = {"kind", "comparison_ref", "branch_ref", "dominates_sink", "checked_ref"}
    if allow_vid:
        fields |= {
            "target_ref",
            "target_reaches_sink",
            "entry_reachable",
            "unique_sink_successor",
        }
    _exact(
        value,
        fields,
        "guard evidence",
    )
    kind = _enum(value["kind"], _GUARDS, "guard kind")
    comparison = _known_ref(value["comparison_ref"], ops, "guard comparison")
    branch = _known_ref(value["branch_ref"], ops, "guard branch")
    checked = _known_ref(value["checked_ref"], ops, "guard checked value")
    if value["dominates_sink"] is not True or branch["opcode"] != "CBRANCH":
        raise ValueError("guard does not dominate the sink")
    if comparison["opcode"] not in {
        "INT_EQUAL",
        "INT_NOTEQUAL",
        "INT_LESS",
        "INT_LESSEQUAL",
        "INT_SLESS",
        "INT_SLESSEQUAL",
    }:
        raise ValueError("guard comparison opcode is invalid")
    if _ref_token(checked) not in _op_input_tokens(ops, comparison):
        raise ValueError("guard comparison does not consume its checked value")
    if _ref_token(comparison) not in _op_input_tokens(ops, branch):
        raise ValueError("guard CBRANCH does not consume its comparison")
    result = {
        "kind": kind,
        "comparison_ref": comparison,
        "branch_ref": branch,
        "checked_ref": checked,
        "sink_ref": sink_ref,
        "dominates_sink": True,
    }
    if allow_vid:
        target = _known_ref(value["target_ref"], ops, "guard branch target")
        if (
            target["opcode"] != "COPY"
            or value["target_reaches_sink"] is not False
            or value["entry_reachable"] is not True
            or value["unique_sink_successor"] is not True
        ):
            raise ValueError("Vid guard CFG proof mismatch")
        result.update(
            {
                "target_ref": target,
                "target_reaches_sink": False,
                "entry_reachable": True,
                "unique_sink_successor": True,
            }
        )
    return result


_SAFETY_PROOF_KINDS = {
    "input-field-readable",
    "source-copy-span",
    "destination-copy-span",
}
_EDGE_PROOF_FIELDS = {
    "comparison_ref",
    "branch_ref",
    "sink_successor_ref",
    "reject_return_ref",
    "sink_comparison_result",
    "dominates_sink",
    "entry_reachable",
    "unique_sink_successor",
    "reject_successor_reaches_sink",
}


def _safety_proof(
    raw: object,
    ops: dict[str, dict[str, object]],
    *,
    source_ref: dict[str, object],
    sink_ref: dict[str, object],
) -> dict[str, object]:
    """Validate one semantic proof; legacy guard labels are derived elsewhere."""
    value = _object(raw, "semantic safety proof")
    kind = _enum(value.get("proof_kind"), _SAFETY_PROOF_KINDS, "proof_kind")
    fields = {"proof_kind", *_EDGE_PROOF_FIELDS}
    if kind == "input-field-readable":
        fields |= {"input_buffer_length_ref", "field_end"}
    elif kind == "source-copy-span":
        fields |= {
            "attacker_length_path",
            "input_buffer_length_ref",
            "remaining_length_ref",
            "field_end",
        }
    else:
        fields |= {
            "attacker_length_path",
            "destination_base_rva",
            "destination_capacity",
            "destination_extent_source",
            "sink_destination_argument_index",
        }
    _exact(value, fields, "semantic safety proof")
    comparison = _known_ref(value["comparison_ref"], ops, "safety comparison")
    branch = _known_ref(value["branch_ref"], ops, "safety branch")
    sink_successor = _known_ref(
        value["sink_successor_ref"], ops, "safe sink successor"
    )
    reject_return = _known_ref(
        value["reject_return_ref"], ops, "reject successor RETURN"
    )
    if comparison["opcode"] not in {"INT_LESS", "INT_LESSEQUAL"}:
        raise ValueError("semantic safety comparison must be unsigned")
    if branch["opcode"] != "CBRANCH" or reject_return["opcode"] != "RETURN":
        raise ValueError("semantic safety control-flow opcodes are invalid")
    if _ref_token(comparison) not in _op_input_tokens(ops, branch):
        raise ValueError("semantic safety CBRANCH does not consume its comparison")
    if (
        not isinstance(value["sink_comparison_result"], bool)
        or value["dominates_sink"] is not True
        or value["entry_reachable"] is not True
        or value["unique_sink_successor"] is not True
        or value["reject_successor_reaches_sink"] is not False
    ):
        raise ValueError("semantic safety edge does not dominate or is incomplete")
    result: dict[str, object] = {
        "proof_kind": kind,
        "comparison_ref": comparison,
        "branch_ref": branch,
        "sink_successor_ref": sink_successor,
        "reject_return_ref": reject_return,
        "sink_comparison_result": value["sink_comparison_result"],
        "dominates_sink": True,
        "entry_reachable": True,
        "unique_sink_successor": True,
        "reject_successor_reaches_sink": False,
        "sink_ref": sink_ref,
    }
    if kind == "input-field-readable":
        checked = _known_ref(
            value["input_buffer_length_ref"], ops, "InputBufferLength proof source"
        )
        if checked["opcode"] != "LOAD" or _ref_token(checked) not in _op_input_tokens(
            ops, comparison
        ):
            raise ValueError("input-field proof does not compare its exact length LOAD")
        result.update(
            {
                "input_buffer_length_ref": checked,
                "field_end": _integer(value["field_end"], "field_end", 1, 1 << 20),
            }
        )
        return result

    attacker_path = _known_ref_array(
        value["attacker_length_path"], ops, "attacker-length proof path"
    )
    if not attacker_path or attacker_path[0] != source_ref:
        raise ValueError("span proof is not rooted in the selected attacker field")
    _require_continuous_dependency_path(attacker_path, ops, "attacker-length proof")
    if _ref_token(attacker_path[-1]) not in _op_input_tokens(ops, comparison):
        raise ValueError("span comparison does not consume the attacker-length path")
    result["attacker_length_path"] = attacker_path
    if kind == "source-copy-span":
        input_length = _known_ref(
            value["input_buffer_length_ref"], ops, "source-span InputBufferLength"
        )
        remaining = _known_ref(
            value["remaining_length_ref"], ops, "source-span remaining length"
        )
        if input_length["opcode"] != "LOAD" or remaining["opcode"] != "INT_SUB":
            raise ValueError("source-span proof lacks exact LOAD-minus-field-end arithmetic")
        remaining_inputs = _op_input_tokens(ops, remaining)
        if _ref_token(input_length) not in remaining_inputs:
            widening = [
                item["ref"]
                for item in ops.values()
                if _object(item["ref"], "source-span widening")["opcode"] == "INT_ZEXT"
                and _ref_token(input_length)
                in _op_input_tokens(ops, _object(item["ref"], "source-span widening"))
                and _ref_token(_object(item["ref"], "source-span widening"))
                in remaining_inputs
            ]
            if len(widening) != 1:
                raise ValueError(
                    "remaining length is not derived by one direct unsigned widening "
                    "of InputBufferLength"
                )
        if _ref_token(remaining) not in _op_input_tokens(ops, comparison):
            raise ValueError("source-span comparison does not consume remaining length")
        result.update(
            {
                "input_buffer_length_ref": input_length,
                "remaining_length_ref": remaining,
                "field_end": _integer(value["field_end"], "field_end", 1, 1 << 20),
            }
        )
    else:
        if value["destination_extent_source"] != "pdb-static-array":
            raise ValueError("destination capacity must come from an exact PDB static array")
        if value["sink_destination_argument_index"] != 0:
            raise ValueError("copy destination proof must bind C argument zero")
        result.update(
            {
                "destination_base_rva": _rva(
                    value["destination_base_rva"], "destination_base_rva"
                ),
                "destination_capacity": _integer(
                    value["destination_capacity"], "destination_capacity", 1, 1 << 30
                ),
                "destination_extent_source": "pdb-static-array",
                "sink_destination_argument_index": 0,
            }
        )
    return result


def _known_ref(raw: object, ops: dict[str, dict[str, object]], label: str) -> dict[str, object]:
    ref = _ref(raw)
    if _ref_token(ref) not in ops:
        raise ValueError(f"{label} references an unknown op")
    return ref


def _known_ref_array(
    raw: object, ops: dict[str, dict[str, object]], label: str
) -> list[dict[str, object]]:
    if not isinstance(raw, list) or len(raw) > 64:
        raise ValueError(f"{label} must be a bounded array")
    refs = [_known_ref(item, ops, label) for item in raw]
    if len({_ref_token(ref) for ref in refs}) != len(refs):
        raise ValueError(f"{label} must be unique")
    return refs


def _op_input_tokens(
    ops: dict[str, dict[str, object]], ref: dict[str, object]
) -> set[str]:
    return {
        _ref_token(_object(item, "input ref"))
        for item in _list(ops[_ref_token(ref)]["input_refs"], "op input refs")
    }


def _require_continuous_dependency_path(
    refs: list[dict[str, object]], ops: dict[str, dict[str, object]], label: str
) -> None:
    for dependency, consumer in pairwise(refs):
        if _ref_token(dependency) not in _op_input_tokens(ops, consumer):
            raise ValueError(f"{label} dependency path is discontinuous")


def _ref(raw: object) -> dict[str, object]:
    value = _object(raw, "op ref")
    _exact(value, {"function_rva", "instruction_rva", "pcode_order", "opcode"}, "op ref")
    return {
        "function_rva": _rva(value["function_rva"], "function_rva"),
        "instruction_rva": _rva(value["instruction_rva"], "instruction_rva"),
        "pcode_order": _integer(value["pcode_order"], "pcode_order", 0, 65535),
        "opcode": _enum(value["opcode"], _VID_OPCODES, "opcode"),
    }


def _stable_op_id(ref: dict[str, object]) -> int:
    digest = hashlib.sha256(
        b"0verse-windows-ioctl-pcode-op-v2\0" + _ref_token(ref).encode()
    ).digest()
    value = int.from_bytes(digest[:8], "big") & ((1 << 63) - 1)
    return value or 1


def _pe_machine(path: Path) -> tuple[int, str, int]:
    data = path.read_bytes()
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe : pe + 4] != b"PE\0\0":
            raise ValueError
        machine = struct.unpack_from("<H", data, pe + 4)[0]
        optional = pe + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic == 0x20B:
            image_base = struct.unpack_from("<Q", data, optional + 24)[0]
            pointer_size = 8
        elif magic == 0x10B:
            image_base = struct.unpack_from("<I", data, optional + 28)[0]
            pointer_size = 4
        else:
            raise ValueError
    except (IndexError, struct.error, ValueError) as exc:
        raise ValueError("driver is not a supported PE image") from exc
    architectures = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64"}
    if machine not in architectures:
        raise ValueError("driver PE machine is unsupported")
    return image_base, architectures[machine], pointer_size


def _direct_high_pcode_evidence(
    binary: Path,
    pdb: Path,
    ghidra_home: Path,
    driver_name: str,
    handler_name: str,
    image_base: int,
) -> dict[str, Any]:
    """Recover the narrow profile from raw HighFunction operations.

    Decompiled C is intentionally not accepted as operation or dominance
    evidence.  It is used by the caller only for PDB-backed type/body discovery.
    """
    import pyghidra

    from .backends.ghidra import _callee_name

    requested_version = _requested_ghidra_version(ghidra_home)
    pyghidra.start(install_dir=ghidra_home)
    from ghidra.framework import Application

    active_version = str(Application.getApplicationVersion())
    _require_active_ghidra_version(active_version, requested_version)
    with tempfile.TemporaryDirectory(prefix="zeroverse-ioctl-pcode-") as temporary:
        root = Path(temporary)
        target = root / "target.sys"
        shutil.copyfile(binary, target)
        shutil.copyfile(pdb, root / "target.pdb")
        with pyghidra.open_program(str(target)) as flat:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            program = flat.getCurrentProgram()
            monitor = ConsoleTaskMonitor()
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            functions = program.getFunctionManager()
            all_functions = _bounded_functions(functions.getFunctions(True))
            driver = _one_ghidra_function(all_functions, driver_name)
            handler = _one_ghidra_function(all_functions, handler_name)
            surface = _complete_internal_surface(decompiler, all_functions, monitor)
            _driver_high, driver_body, driver_ops = _surface_entry(surface, driver)
            handler_high, handler_body, handler_ops = _surface_entry(surface, handler)

            try:
                from .structtypes import harvest_structs

                type_material = json.dumps(harvest_structs(program), sort_keys=True)
            except Exception as exc:
                raise ValueError("PDB-backed WDM type harvesting failed") from exc

            _reject_unresolved_surface_calls(
                surface, functions, program, monitor, _callee_name
            )

            handler_address = int(handler.getEntryPoint().getOffset())
            registration_candidates = []
            for op in driver_ops:
                if str(op.getMnemonic()) != "STORE" or op.getNumInputs() < 3:
                    continue
                address_def = op.getInput(1).getDef()
                value_def = op.getInput(2).getDef()
                address_constants = _dependency_constants(address_def)
                value_constants = _dependency_constants(value_def)
                if {14, 8} <= address_constants and handler_address in value_constants:
                    registration_candidates.append(op)
            registration = _one_op(
                registration_candidates, "one exact MajorFunction[14] High-P-Code STORE"
            )

            comparison_candidates = [
                op
                for op in handler_ops
                if str(op.getMnemonic()) in {"INT_EQUAL", "INT_NOTEQUAL"}
                and any(node.isConstant() and int(node.getOffset()) > 0xFFFF for node in (
                    op.getInput(index) for index in range(op.getNumInputs())
                ))
            ]
            comparison = _one_op(
                comparison_candidates, "one exact constant IOCTL comparison"
            )
            ioctl_constants = {
                int(comparison.getInput(index).getOffset())
                for index in range(comparison.getNumInputs())
                if comparison.getInput(index).isConstant()
                and int(comparison.getInput(index).getOffset()) > 0xFFFF
            }
            if len(ioctl_constants) != 1:
                raise ValueError("IOCTL High-P-Code comparison constant is ambiguous")
            ioctl_code = next(iter(ioctl_constants))
            branches = [
                op
                for op in handler_ops
                if str(op.getMnemonic()) == "CBRANCH"
                and any(
                    op.getInput(index).getDef() is not None
                    and str(op.getInput(index).getDef().getSeqnum())
                    == str(comparison.getSeqnum())
                    for index in range(op.getNumInputs())
                )
            ]
            branch = _one_op(branches, "one direct IOCTL comparison branch")
            supported_sinks = {"RtlCopyMemory", "memcpy", "memmove"}
            sink_candidates: list[tuple[Any, str]] = []
            for op in handler_ops:
                if str(op.getMnemonic()) != "CALL" or op.getNumInputs() < 4:
                    continue
                name, resolved = _callee_name(op.getInput(0), functions, program, monitor)
                if resolved and name is not None and name in supported_sinks:
                    sink_candidates.append((op, name))
            if len(sink_candidates) != 1:
                raise ValueError("one directly resolved supported copy sink was not recovered")
            sink, sink_function = sink_candidates[0]

            length_tail = sink.getInput(3).getDef()
            if length_tail is None:
                raise ValueError("copy length has no High-P-Code definition")
            taint_ops = _linear_source_path(length_tail)
            if str(taint_ops[0].getMnemonic()) != "LOAD":
                raise ValueError("copy length is not rooted in one direct High-P-Code LOAD")
            field_offset = _direct_irp_system_buffer_offset(taint_ops[0], program)
            if not _dominates(handler_high, branch, sink):
                raise ValueError("IOCTL branch does not dominate the selected copy sink")
            ioctl_match_result = str(comparison.getMnemonic()) == "INT_EQUAL"
            ioctl_match_marker, ioctl_reject_return = _semantic_branch_gate(
                handler_high,
                handler_ops,
                branch,
                sink,
                safe_comparison_result=ioctl_match_result,
            )

            guard_comparisons = [
                op
                for op in handler_ops
                if op is not comparison
                and str(op.getMnemonic())
                in {"INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL"}
            ]
            proof_facts: list[dict[str, Any]] = []
            for guard_comparison in guard_comparisons:
                guard_branches = [
                    op
                    for op in handler_ops
                    if str(op.getMnemonic()) == "CBRANCH"
                    and any(
                        op.getInput(index).getDef() is not None
                        and str(op.getInput(index).getDef().getSeqnum())
                        == str(guard_comparison.getSeqnum())
                        for index in range(op.getNumInputs())
                    )
                ]
                guard_branch = _one_op(
                    guard_branches,
                    "one direct semantic guard branch",
                )
                proof: dict[str, Any] | None = None
                proof_failures: list[str] = []
                try:
                    checked, safe_result = _exact_input_buffer_length_guard(
                        guard_comparison,
                        program,
                        minimum_length=field_offset + 4,
                    )
                    proof = {
                        "proof_kind": "input-field-readable",
                        "comparison": guard_comparison,
                        "branch": guard_branch,
                        "input_buffer_length": checked,
                        "field_end": field_offset + 4,
                        "extra_ops": [checked],
                        "safe_result": safe_result,
                    }
                except ValueError as exc:
                    proof_failures.append(f"input-field-readable={exc}")
                if proof is None:
                    try:
                        attacker_path, input_length_path, remaining, safe_result = (
                            _exact_source_span_guard(
                                guard_comparison,
                                taint_ops[0],
                                program,
                                field_end=field_offset + 4,
                            )
                        )
                        proof = {
                            "proof_kind": "source-copy-span",
                            "comparison": guard_comparison,
                            "branch": guard_branch,
                            "attacker_path": attacker_path,
                            "input_buffer_length": input_length_path[0],
                            "remaining_length": remaining,
                            "field_end": field_offset + 4,
                            "extra_ops": [*attacker_path, *input_length_path, remaining],
                            "safe_result": safe_result,
                        }
                    except ValueError as exc:
                        proof_failures.append(f"source-copy-span={exc}")
                if proof is None:
                    try:
                        destination_base = _exact_static_destination_extent(
                            sink, program, capacity=64
                        )
                        attacker_path, safe_result = _exact_destination_span_guard(
                            guard_comparison, taint_ops[0], capacity=64
                        )
                        proof = {
                            "proof_kind": "destination-copy-span",
                            "comparison": guard_comparison,
                            "branch": guard_branch,
                            "attacker_path": attacker_path,
                            "destination_base": destination_base,
                            "destination_capacity": 64,
                            "extra_ops": list(attacker_path),
                            "safe_result": safe_result,
                        }
                    except ValueError as exc:
                        proof_failures.append(f"destination-copy-span={exc}")
                if proof is None:
                    comparison_inputs = [
                        (
                            f"const:{int(guard_comparison.getInput(index).getOffset())}"
                            if guard_comparison.getInput(index).isConstant()
                            else (
                                str(guard_comparison.getInput(index).getDef().getMnemonic())
                                if guard_comparison.getInput(index).getDef() is not None
                                else str(guard_comparison.getInput(index))
                            )
                        )
                        for index in range(guard_comparison.getNumInputs())
                    ]
                    input_details: list[str] = []
                    for index in range(guard_comparison.getNumInputs()):
                        definition = guard_comparison.getInput(index).getDef()
                        if definition is None:
                            continue
                        detail = []
                        for child_index in range(definition.getNumInputs()):
                            child = definition.getInput(child_index)
                            detail.append(
                                f"const:{int(child.getOffset())}"
                                if child.isConstant()
                                else (
                                    str(child.getDef().getMnemonic())
                                    if child.getDef() is not None
                                    else str(child)
                                )
                            )
                        input_details.append(
                            f"input{index}:{definition.getMnemonic()}={detail}"
                        )
                    raise ValueError(
                        "one semantic raw High-P-Code guard was not recovered: "
                        f"{guard_comparison.getMnemonic()} {comparison_inputs} at "
                        f"{guard_comparison.getSeqnum()} ({', '.join(input_details)}); "
                        f"{'; '.join(proof_failures)}"
                    )
                safe_marker, reject_return = _semantic_branch_gate(
                    handler_high,
                    handler_ops,
                    guard_branch,
                    sink,
                    safe_comparison_result=cast(bool, proof["safe_result"]),
                )
                proof["safe_marker"] = safe_marker
                proof["reject_return"] = reject_return
                proof["extra_ops"].extend((safe_marker, reject_return))
                proof_facts.append(proof)
            proof_kinds = [str(fact["proof_kind"]) for fact in proof_facts]
            if len(proof_kinds) != len(set(proof_kinds)):
                raise ValueError("live semantic safety proof kind is duplicated")
            input_guards = [
                fact for fact in proof_facts if fact["proof_kind"] == "input-field-readable"
            ]
            if "InputBufferLength" in handler_body and len(input_guards) != 1:
                raise ValueError(
                    "one exact edge-safe InputBufferLength field proof was not recovered"
                )
            if "InputBufferLength" not in handler_body and input_guards:
                raise ValueError("raw guard evidence lacks a typed InputBufferLength source")
            audit_facts: list[tuple[Any, Any, Any, tuple[str, ...]]] = [
                (
                    fact["comparison"],
                    fact["branch"],
                    fact.get("input_buffer_length", taint_ops[0]),
                    (),
                )
                for fact in proof_facts
            ]
            _audit_complete_ioctl_surface(
                surface,
                driver,
                handler,
                registration,
                comparison,
                branch,
                handler_address,
                guard_facts=audit_facts,
            )

            selected = _dependency_ops(registration)
            selected.extend(
                (comparison, branch, ioctl_match_marker, ioctl_reject_return)
            )
            selected.extend(taint_ops)
            selected.append(sink)
            for proof in proof_facts:
                selected.extend((proof["comparison"], proof["branch"]))
                selected.extend(proof["extra_ops"])
            unique = {str(op.getSeqnum()): op for op in selected}
            ref_by_seq = {
                sequence: _operation_ref(op, driver if op in driver_ops else handler, image_base)
                for sequence, op in unique.items()
            }
            raw_ops = []
            for sequence, op in unique.items():
                inputs = []
                for index in range(op.getNumInputs()):
                    definition = op.getInput(index).getDef()
                    if definition is not None:
                        ref = ref_by_seq.get(str(definition.getSeqnum()))
                        if ref is not None:
                            inputs.append(ref)
                inputs = sorted({_ref_token(ref): ref for ref in inputs}.values(), key=_ref_key)
                raw_ops.append({"ref": ref_by_seq[sequence], "input_refs": inputs})
            raw_ops.sort(key=lambda item: _ref_key(cast(dict[str, object], item["ref"])))
            taint_path = [ref_by_seq[str(op.getSeqnum())] for op in taint_ops]
            taint_path.append(ref_by_seq[str(sink.getSeqnum())])
            registration_ref = ref_by_seq[str(registration.getSeqnum())]
            address_def = registration.getInput(1).getDef()
            target_def = registration.getInput(2).getDef()
            if address_def is None or target_def is None:
                raise ValueError("registration STORE has unbound address or target")
            sink_ref = ref_by_seq[str(sink.getSeqnum())]
            safety_proofs = []
            for proof in proof_facts:
                raw_proof: dict[str, object] = {
                    "proof_kind": proof["proof_kind"],
                    "comparison_ref": ref_by_seq[str(proof["comparison"].getSeqnum())],
                    "branch_ref": ref_by_seq[str(proof["branch"].getSeqnum())],
                    "sink_successor_ref": ref_by_seq[str(proof["safe_marker"].getSeqnum())],
                    "reject_return_ref": ref_by_seq[str(proof["reject_return"].getSeqnum())],
                    "sink_comparison_result": proof["safe_result"],
                    "dominates_sink": True,
                    "entry_reachable": True,
                    "unique_sink_successor": True,
                    "reject_successor_reaches_sink": False,
                }
                if proof["proof_kind"] == "input-field-readable":
                    raw_proof.update(
                        {
                            "input_buffer_length_ref": ref_by_seq[
                                str(proof["input_buffer_length"].getSeqnum())
                            ],
                            "field_end": proof["field_end"],
                        }
                    )
                elif proof["proof_kind"] == "source-copy-span":
                    raw_proof.update(
                        {
                            "attacker_length_path": [
                                ref_by_seq[str(op.getSeqnum())] for op in proof["attacker_path"]
                            ],
                            "input_buffer_length_ref": ref_by_seq[
                                str(proof["input_buffer_length"].getSeqnum())
                            ],
                            "remaining_length_ref": ref_by_seq[
                                str(proof["remaining_length"].getSeqnum())
                            ],
                            "field_end": proof["field_end"],
                        }
                    )
                else:
                    raw_proof.update(
                        {
                            "attacker_length_path": [
                                ref_by_seq[str(op.getSeqnum())] for op in proof["attacker_path"]
                            ],
                            "destination_base_rva": (
                                f"0x{cast(int, proof['destination_base']) - image_base:x}"
                            ),
                            "destination_capacity": proof["destination_capacity"],
                            "destination_extent_source": "pdb-static-array",
                            "sink_destination_argument_index": 0,
                        }
                    )
                safety_proofs.append(raw_proof)
            return {
                "handler_name": str(handler.getName()),
                "driver_body": driver_body,
                "handler_body": handler_body,
                "type_material": type_material,
                "ioctl_code": ioctl_code,
                "handler_rva": f"0x{handler_address - image_base:x}",
                "registration_rva": registration_ref["instruction_rva"],
                "store_ref": registration_ref,
                "registration_address_refs": [ref_by_seq[str(address_def.getSeqnum())]],
                "registration_target_refs": [ref_by_seq[str(target_def.getSeqnum())]],
                "ioctl_compare_ref": ref_by_seq[str(comparison.getSeqnum())],
                "ioctl_branch_ref": ref_by_seq[str(branch.getSeqnum())],
                "ioctl_dominates_sink": True,
                "ioctl_match_successor_ref": ref_by_seq[
                    str(ioctl_match_marker.getSeqnum())
                ],
                "ioctl_reject_return_ref": ref_by_seq[
                    str(ioctl_reject_return.getSeqnum())
                ],
                "ioctl_match_comparison_result": ioctl_match_result,
                "ops": raw_ops,
                "length_ref": taint_path[0],
                "field_offset": field_offset,
                "sink_function": sink_function,
                "sink_rva": sink_ref["instruction_rva"],
                "sink_ref": sink_ref,
                "taint_path": taint_path,
                "safety_proofs": safety_proofs,
            }


def _one_ghidra_function(functions: list[Any], requested: str) -> Any:
    matches = [
        function
        for function in functions
        if str(function.getName()) == requested
        or requested.endswith(f"::{function.getName()}")
        or str(function.getName()).endswith(f"::{requested}")
    ]
    if len(matches) != 1:
        raise ValueError(f"one raw High-P-Code {requested} function was not recovered")
    return matches[0]


def _vid_op(
    ops: list[Any], image_base: int, rva: int, opcode: str, order: int
) -> Any:
    matches = [
        op
        for op in ops
        if str(op.getMnemonic()) == opcode
        and int(op.getSeqnum().getTarget().getOffset()) - image_base == rva
        and int(op.getSeqnum().getTime()) == order
    ]
    return _one_op(matches, f"one Vid {opcode} at 0x{rva:x}:{order}")


def _vid_input(op: Any, index: int) -> Any:
    if index < 0 or index >= op.getNumInputs():
        raise ValueError("required positional Vid High-P-Code input is absent")
    return op.getInput(index)


def _vid_constant(op: Any, index: int, expected: int) -> None:
    value = _vid_input(op, index)
    if not value.isConstant() or (int(value.getOffset()) & 0xFFFFFFFFFFFFFFFF) != expected:
        raise ValueError("Vid High-P-Code positional constant mismatch")


def _vid_address(op: Any, index: int, expected: int) -> None:
    value = _vid_input(op, index)
    if not value.isAddress() or int(value.getAddress().getOffset()) != expected:
        raise ValueError("Vid High-P-Code positional address mismatch")


def _vid_definition(op: Any, index: int, expected: Any) -> None:
    definition = _vid_input(op, index).getDef()
    if definition is None or str(definition.getSeqnum()) != str(expected.getSeqnum()):
        raise ValueError("Vid High-P-Code positional definition mismatch")


def _vid_name(op: Any, index: int, expected: str) -> None:
    high = _vid_input(op, index).getHigh()
    if high is None or str(high.getName()) != expected:
        raise ValueError("Vid typed positional parameter mismatch")


def _vid_branch_gate(
    high: Any,
    branch: Any,
    target_marker: Any,
    sink: Any,
    *,
    target_reaches_sink: bool,
) -> None:
    blocks = list(high.getBasicBlocks())
    by_index = {int(block.getIndex()): block for block in blocks}
    if 0 not in by_index:
        raise ValueError("Vid CFG has no entry block zero")
    edges = {
        int(block.getIndex()): {
            int(block.getOut(index).getIndex()) for index in range(block.getOutSize())
        }
        for block in blocks
    }
    branch_block = int(branch.getParent().getIndex())
    sink_block = int(sink.getParent().getIndex())
    successors = edges.get(branch_block, set())
    target_block = int(target_marker.getParent().getIndex())
    if len(successors) != 2 or target_block not in successors:
        raise ValueError("Vid CBRANCH target is not an exact CFG successor")
    if not _vid_reachable(edges, 0, branch_block) or not _vid_reachable(edges, 0, sink_block):
        raise ValueError("Vid guard or sink is disconnected from CFG entry")
    reachability = {
        successor: _vid_reachable(edges, successor, sink_block)
        for successor in successors
    }
    if sum(reachability.values()) != 1 or reachability[target_block] is not target_reaches_sink:
        raise ValueError("Vid CBRANCH taken/fallthrough polarity does not gate the sink")
    if not _dominates(high, branch, sink):
        raise ValueError("Vid CBRANCH does not dominate the selected sink")


def _vid_reachable(edges: dict[int, set[int]], start: int, target: int) -> bool:
    pending = [start]
    seen: set[int] = set()
    while pending:
        node = pending.pop()
        if node == target:
            return True
        if node not in seen:
            seen.add(node)
            pending.extend(edges.get(node, set()) - seen)
    return False


def _semantic_branch_gate(
    high: Any,
    operations: list[Any],
    branch: Any,
    sink: Any,
    *,
    safe_comparison_result: bool,
) -> tuple[Any, Any]:
    """Bind comparison truth to the sole sink-reaching CFG edge and reject RETURN."""
    blocks = list(high.getBasicBlocks())
    by_index = {int(block.getIndex()): block for block in blocks}
    entries = [index for index, block in by_index.items() if int(block.getInSize()) == 0]
    if len(entries) != 1:
        raise ValueError("semantic guard CFG entry is ambiguous")
    edges = {
        index: {
            int(block.getOut(out_index).getIndex())
            for out_index in range(block.getOutSize())
        }
        for index, block in by_index.items()
    }
    branch_block = int(branch.getParent().getIndex())
    sink_block = int(sink.getParent().getIndex())
    successors = edges.get(branch_block, set())
    if len(successors) != 2 or not _vid_reachable(edges, entries[0], branch_block):
        raise ValueError("semantic guard must have two entry-reachable CFG successors")
    target_node = branch.getInput(0)
    if not bool(target_node.isAddress()):
        raise ValueError("semantic CBRANCH lacks an exact taken target address")
    by_block: dict[int, list[Any]] = {index: [] for index in by_index}
    for operation in operations:
        parent = operation.getParent()
        if parent is not None and int(parent.getIndex()) in by_block:
            by_block[int(parent.getIndex())].append(operation)
    true_block = branch.getParent().getTrueOut()
    false_block = branch.getParent().getFalseOut()
    if true_block is None or false_block is None:
        raise ValueError("semantic CBRANCH lacks exact true and false CFG edges")
    true_successor = int(true_block.getIndex())
    false_successor = int(false_block.getIndex())
    if (
        {true_successor, false_successor} != successors
        or true_successor == false_successor
    ):
        raise ValueError("semantic CBRANCH true/false edges do not match its successors")
    safe_successor = true_successor if safe_comparison_result else false_successor
    reject_successor = false_successor if safe_comparison_result else true_successor
    reachability = {
        successor: _vid_reachable(edges, successor, sink_block) for successor in successors
    }
    if (
        sum(reachability.values()) != 1
        or reachability[safe_successor] is not True
        or reachability[reject_successor] is not False
        or not _dominates(high, branch, sink)
    ):
        raise ValueError(
            "semantic guard polarity does not gate the selected sink: "
            f"safe_result={safe_comparison_result}, true={true_successor}, "
            f"false={false_successor}, safe={safe_successor}, "
            f"reject={reject_successor}, reachability={reachability}, "
            f"dominates={_dominates(high, branch, sink)}, branch={branch}"
        )
    safe_ops = sorted(
        by_block[safe_successor],
        key=lambda operation: (
            int(operation.getSeqnum().getTarget().getOffset()),
            int(operation.getSeqnum().getTime()),
        ),
    )
    if not safe_ops:
        raise ValueError("semantic safe successor has no retainable High-P-Code marker")
    reject_returns = [
        operation
        for operation in operations
        if str(operation.getMnemonic()) == "RETURN"
        and _vid_reachable(edges, reject_successor, int(operation.getParent().getIndex()))
    ]
    if len(reject_returns) != 1:
        raise ValueError("semantic reject successor does not reach one exact RETURN")
    return safe_ops[0], reject_returns[0]


def _decompile_high(decompiler: Any, function: Any, monitor: Any) -> tuple[Any, str]:
    result = decompiler.decompileFunction(function, 60, monitor)
    high = result.getHighFunction() if result is not None else None
    if high is None:
        raise ValueError(f"raw High-P-Code unavailable for {function.getName()}")
    decompiled = result.getDecompiledFunction()
    if decompiled is None:
        raise ValueError(f"typed decompiled body unavailable for {function.getName()}")
    return high, str(decompiled.getC())


def _requested_ghidra_version(home: Path) -> str:
    properties = home / "Ghidra" / "application.properties"
    if properties.is_symlink() or not properties.is_file():
        raise ValueError("requested Ghidra application properties are unavailable")
    matches = [
        line.split("=", 1)[1].strip()
        for line in properties.read_text(encoding="utf-8").splitlines()
        if line.startswith("application.version=")
    ]
    if len(matches) != 1 or not matches[0]:
        raise ValueError("requested Ghidra application version is unavailable")
    return matches[0]


def _require_active_ghidra_version(active: str, requested: str) -> None:
    if active != requested:
        raise ValueError(
            "active PyGhidra application version does not match requested Ghidra home"
        )


def _require_no_unsupported_live_guard_sources(handler_body: str) -> None:
    if any(
        guard_name in handler_body
        for guard_name in ("OutputBufferLength", "PreviousMode")
    ):
        raise ValueError("live IOCTL extraction cannot emit unimplemented guard evidence")


def _exact_input_buffer_length_guard(
    comparison: Any,
    program: Any,
    *,
    minimum_length: int,
) -> tuple[Any, bool]:
    """Return the exact PDB-bound length LOAD and its sink-safe comparison result.

    Only the canonical unsigned forms ``length < minimum``,
    ``length <= minimum - 1``, ``minimum <= length`` and
    ``minimum - 1 < length`` are accepted. The caller separately proves that
    the consuming CBRANCH dominates the selected sink.
    """
    mnemonic = str(comparison.getMnemonic())
    if mnemonic not in {"INT_LESS", "INT_LESSEQUAL"} or comparison.getNumInputs() != 2:
        raise ValueError("unsupported InputBufferLength guard comparison")
    left, right = comparison.getInput(0), comparison.getInput(1)
    forms = (
        (left, right, "INT_LESS", minimum_length, False),
        (left, right, "INT_LESSEQUAL", minimum_length - 1, False),
        (right, left, "INT_LESSEQUAL", minimum_length, True),
        (right, left, "INT_LESS", minimum_length - 1, True),
    )
    matches: list[tuple[Any, bool]] = []
    for checked_node, constant_node, expected_mnemonic, constant, safe_result in forms:
        if mnemonic != expected_mnemonic:
            continue
        if not bool(constant_node.isConstant()) or int(constant_node.getOffset()) != constant:
            continue
        checked = _strip_direct_passthrough(
            checked_node, "InputBufferLength guard value"
        ).getDef()
        if checked is None or str(checked.getMnemonic()) != "LOAD":
            continue
        try:
            _require_direct_input_buffer_length_load(checked, program)
        except ValueError:
            continue
        matches.append((checked, safe_result))
    unique = {str(operation.getSeqnum()): (operation, result) for operation, result in matches}
    if len(unique) != 1:
        raise ValueError(
            "guard comparison is not bound to one exact PDB-backed InputBufferLength LOAD"
        )
    return next(iter(unique.values()))


def _passthrough_path_from_source(node: Any, source: Any, label: str) -> list[Any]:
    reverse: list[Any] = []
    current = node.getDef()
    while current is not None:
        reverse.append(current)
        if str(current.getSeqnum()) == str(source.getSeqnum()):
            reverse.reverse()
            return reverse
        if str(current.getMnemonic()) not in {"COPY", "CAST", "INT_ZEXT", "SUBPIECE"}:
            break
        definitions = [
            current.getInput(index).getDef()
            for index in range(current.getNumInputs())
            if current.getInput(index).getDef() is not None
        ]
        if len(definitions) != 1 or len(reverse) >= 16:
            break
        current = definitions[0]
    raise ValueError(f"{label} is not a bounded direct path from the attacker field")


def _exact_source_span_guard(
    comparison: Any,
    source: Any,
    program: Any,
    *,
    field_end: int,
) -> tuple[list[Any], list[Any], Any, bool]:
    """Recognize exactly attacker <= InputBufferLength - field_end."""
    mnemonic = str(comparison.getMnemonic())
    if mnemonic not in {"INT_LESS", "INT_LESSEQUAL"} or comparison.getNumInputs() != 2:
        raise ValueError("unsupported source-span comparison")
    left, right = comparison.getInput(0), comparison.getInput(1)
    forms = (
        (right, left, "INT_LESS", False),
        (left, right, "INT_LESSEQUAL", True),
    )
    matches: list[tuple[list[Any], list[Any], Any, bool]] = []
    failures: list[str] = []
    for attacker_node, remaining_node, expected, safe_result in forms:
        if mnemonic != expected:
            continue
        try:
            attacker_path = _passthrough_path_from_source(
                attacker_node, source, "source-span attacker length"
            )
        except ValueError as exc:
            failures.append(str(exc))
            continue
        remaining = remaining_node.getDef()
        if (
            remaining is None
            or str(remaining.getMnemonic()) != "INT_SUB"
            or remaining.getNumInputs() != 2
        ):
            failures.append("remaining operand is not one direct INT_SUB")
            continue
        constant = remaining.getInput(1)
        if not bool(constant.isConstant()) or int(constant.getOffset()) != field_end:
            failures.append("INT_SUB does not subtract the exact field end")
            continue
        length_node = _strip_direct_passthrough(
            remaining.getInput(0), "source-span InputBufferLength"
        )
        widening = length_node.getDef()
        length_path: list[Any] = []
        if (
            widening is not None
            and str(widening.getMnemonic()) == "INT_ZEXT"
            and widening.getNumInputs() == 1
        ):
            length_node = _strip_direct_passthrough(
                widening.getInput(0), "source-span widened InputBufferLength"
            )
            length_path.append(widening)
        input_length = length_node.getDef()
        if input_length is None or str(input_length.getMnemonic()) != "LOAD":
            failures.append("INT_SUB left operand is not one direct length LOAD")
            continue
        try:
            _require_direct_input_buffer_length_load(input_length, program)
        except ValueError as exc:
            failures.append(str(exc))
            continue
        matches.append(
            (attacker_path, [input_length, *reversed(length_path)], remaining, safe_result)
        )
    unique = {
        (str(item[1][0].getSeqnum()), str(item[2].getSeqnum()), item[3]): item
        for item in matches
    }
    if len(unique) != 1:
        detail = f": {'; '.join(failures)}" if failures else ""
        raise ValueError(
            f"one exact nonwrapping source-span guard was not recovered{detail}"
        )
    return next(iter(unique.values()))


def _exact_destination_span_guard(
    comparison: Any,
    source: Any,
    *,
    capacity: int,
) -> tuple[list[Any], bool]:
    """Recognize exactly attacker <= the independently proven destination capacity.

    The unsigned exclusive form ``attacker < capacity + 1`` is equivalent and
    is accepted because the independently proven capacity is strictly bounded.
    """
    mnemonic = str(comparison.getMnemonic())
    if mnemonic not in {"INT_LESS", "INT_LESSEQUAL"} or comparison.getNumInputs() != 2:
        raise ValueError("unsupported destination-span comparison")
    left, right = comparison.getInput(0), comparison.getInput(1)
    forms = (
        (right, left, "INT_LESS", capacity, False),
        (left, right, "INT_LESSEQUAL", capacity, True),
        (left, right, "INT_LESS", capacity + 1, True),
    )
    matches: list[tuple[list[Any], bool]] = []
    for attacker_node, constant_node, expected, exact_capacity, safe_result in forms:
        if (
            mnemonic != expected
            or not bool(constant_node.isConstant())
            or int(constant_node.getOffset()) != exact_capacity
        ):
            continue
        try:
            path = _passthrough_path_from_source(
                attacker_node, source, "destination-span attacker length"
            )
        except ValueError:
            continue
        matches.append((path, safe_result))
    unique = {(str(item[0][-1].getSeqnum()), item[1]): item for item in matches}
    if len(unique) != 1:
        raise ValueError("one exact destination-span guard was not recovered")
    return next(iter(unique.values()))


def _exact_static_destination_extent(sink: Any, program: Any, *, capacity: int) -> int:
    """Bind CALL argument zero to one PDB-named static array of exact byte extent."""
    if sink.getNumInputs() < 2:
        raise ValueError("copy sink lacks destination argument zero")
    symbols = program.getSymbolTable().getSymbols("KernelSink")
    matches = []
    while symbols.hasNext():
        matches.append(symbols.next())
    if len(matches) != 1:
        raise ValueError("copy destination lacks one unique PDB KernelSink symbol")
    address = matches[0].getAddress()
    if _exact_pointer_value(sink.getInput(1)) != int(address.getOffset()):
        raise ValueError("copy destination does not resolve to the PDB KernelSink address")
    data = program.getListing().getDataAt(address)
    if data is None or int(data.getLength()) != capacity:
        raise ValueError("PDB KernelSink static array extent does not match capacity")
    return int(address.getOffset())


def _exact_pointer_value(node: Any, *, depth: int = 0) -> int:
    """Resolve a bounded constant pointer expression without accepting PHI/arithmetic."""
    if depth >= 8:
        raise ValueError("copy destination pointer expression is too deep")
    if bool(node.isAddress()) or bool(node.isConstant()):
        return int(node.getOffset())
    definition = node.getDef()
    if definition is None:
        raise ValueError("copy destination pointer has no exact definition")
    mnemonic = str(definition.getMnemonic())
    if mnemonic in {"COPY", "CAST"} and definition.getNumInputs() == 1:
        return _exact_pointer_value(definition.getInput(0), depth=depth + 1)
    if mnemonic in {"PTRSUB", "INT_ADD"} and definition.getNumInputs() == 2:
        offset = definition.getInput(1)
        if not bool(offset.isConstant()):
            raise ValueError("copy destination pointer offset is not constant")
        base = _exact_pointer_value(definition.getInput(0), depth=depth + 1)
        result = base + int(offset.getOffset())
        if not 0 <= result < 1 << 64:
            raise ValueError("copy destination pointer arithmetic overflows")
        return result
    raise ValueError("copy destination pointer uses unsupported arithmetic or PHI")


def _require_direct_input_buffer_length_load(value_load: Any, program: Any) -> None:
    if str(value_load.getMnemonic()) != "LOAD" or value_load.getNumInputs() < 2:
        raise ValueError("InputBufferLength source is not a High-P-Code LOAD")
    stack_value = _strip_exact_ptrsub_path(
        value_load.getInput(1),
        reversed_offsets=(4, 0, 8),
        label="InputBufferLength",
    )
    stack_load = stack_value.getDef()
    if (
        stack_load is None
        or str(stack_load.getMnemonic()) != "LOAD"
        or stack_load.getNumInputs() < 2
    ):
        raise ValueError("InputBufferLength does not flow from CurrentStackLocation")
    irp_address = _strip_zero_offset_pointer_address(
        stack_load.getInput(1),
        expected_offset=8,
        label="CurrentStackLocation",
    )
    if irp_address.getDef() is not None:
        raise ValueError("CurrentStackLocation uses unsupported arithmetic or PHI")
    if not bool(irp_address.isRegister()) or int(irp_address.getSize()) != 8:
        raise ValueError("CurrentStackLocation root is not the x64 WDM second parameter")
    try:
        register = program.getRegister(irp_address.getAddress(), int(irp_address.getSize()))
    except TypeError:
        register = program.getRegister(irp_address.getAddress())
    if register is None or str(register.getName()).upper() != "RDX":
        raise ValueError("CurrentStackLocation root is not the x64 WDM second parameter RDX")
    _require_pdb_struct_field(program, "_IRP", "CurrentStackLocation", 8)
    _require_pdb_nested_field(
        program,
        "_IO_STACK_LOCATION",
        (("Parameters", 8), ("DeviceIoControl", 0), ("InputBufferLength", 4)),
        expected_offset=12,
    )


def _strip_exact_ptrsub_path(
    node: Any, *, reversed_offsets: tuple[int, ...], label: str
) -> Any:
    current = _strip_direct_passthrough(node, f"{label} address")
    for expected_offset in reversed_offsets:
        definition = current.getDef()
        if (
            definition is None
            or str(definition.getMnemonic()) != "PTRSUB"
            or definition.getNumInputs() != 2
        ):
            raise ValueError(f"{label} address lacks the exact PDB field path")
        offset = definition.getInput(1)
        if not bool(offset.isConstant()) or int(offset.getOffset()) != expected_offset:
            raise ValueError(f"{label} address does not match the exact PDB field path")
        current = _strip_direct_passthrough(
            definition.getInput(0), f"{label} address"
        )
    return current


def _strip_zero_offset_pointer_address(
    node: Any, *, expected_offset: int, label: str
) -> Any:
    current = _strip_direct_passthrough(node, label)
    definition = current.getDef()
    if definition is None:
        if expected_offset == 0:
            return current
        raise ValueError(f"{label} address lacks exact PDB offset {expected_offset}")
    if str(definition.getMnemonic()) != "PTRSUB" or definition.getNumInputs() != 2:
        raise ValueError(f"{label} address uses unsupported arithmetic")
    offset = definition.getInput(1)
    if not bool(offset.isConstant()) or int(offset.getOffset()) != expected_offset:
        raise ValueError(f"{label} PTRSUB does not use exact PDB offset {expected_offset}")
    return _strip_direct_passthrough(definition.getInput(0), label)


def _bounded_functions(iterator: Any) -> list[Any]:
    result: list[Any] = []
    while iterator.hasNext():
        if len(result) >= cast(int, _CONFIG["max_internal_functions"]):
            raise ValueError("Ghidra function surface exceeds the configured cap")
        result.append(iterator.next())
    return result


def _high_ops(high: Any, *, remaining: int | None = None) -> list[Any]:
    result: list[Any] = []
    iterator = high.getPcodeOps()
    while iterator.hasNext():
        if len(result) >= cast(int, _CONFIG["max_ops_per_function"]):
            raise ValueError("High-P-Code function exceeds the configured operation cap")
        if remaining is not None and len(result) >= remaining:
            raise ValueError("High-P-Code program exceeds the configured total operation cap")
        result.append(iterator.next())
    return result


def _complete_internal_surface(
    decompiler: Any, functions: list[Any], monitor: Any
) -> dict[int, tuple[Any, Any, str, list[Any]]]:
    surface: dict[int, tuple[Any, Any, str, list[Any]]] = {}
    total = 0
    total_cap = cast(int, _CONFIG["max_total_ops"])
    for function in functions:
        if bool(function.isExternal()):
            continue
        high, body = _decompile_high(decompiler, function, monitor)
        ops = _high_ops(high, remaining=total_cap - total)
        total += len(ops)
        address = int(function.getEntryPoint().getOffset())
        if address in surface:
            raise ValueError("Ghidra internal function surface is ambiguous")
        surface[address] = (function, high, body, ops)
    if not surface:
        raise ValueError("Ghidra internal function surface is unavailable")
    return surface


def _surface_entry(
    surface: dict[int, tuple[Any, Any, str, list[Any]]], function: Any
) -> tuple[Any, str, list[Any]]:
    address = int(function.getEntryPoint().getOffset())
    try:
        _function, high, body, ops = surface[address]
    except KeyError as exc:
        raise ValueError("selected function is outside the complete internal surface") from exc
    return high, body, ops


def _reject_unresolved_surface_calls(
    surface: dict[int, tuple[Any, Any, str, list[Any]]],
    functions: Any,
    program: Any,
    monitor: Any,
    callee_name: Any,
) -> None:
    for _function, _high, _body, ops in surface.values():
        for op in ops:
            mnemonic = str(op.getMnemonic())
            if mnemonic in {"CALLIND", "CALLOTHER"}:
                raise ValueError("live IOCTL extraction rejects indirect High-P-Code calls")
            if mnemonic == "CALL":
                _name, resolved = callee_name(
                    op.getInput(0), functions, program, monitor
                )
                if not resolved:
                    raise ValueError(
                        "live IOCTL extraction rejects unresolved High-P-Code calls"
                    )


def _audit_complete_ioctl_surface(
    surface: dict[int, tuple[Any, Any, str, list[Any]]],
    driver: Any,
    handler: Any,
    registration: Any,
    comparison: Any,
    branch: Any,
    handler_address: int,
    *,
    guard_facts: list[tuple[Any, Any, Any, tuple[str, ...]]] | None = None,
) -> None:
    guards = guard_facts or []
    driver_address = int(driver.getEntryPoint().getOffset())
    handler_entry = int(handler.getEntryPoint().getOffset())
    major_references: list[tuple[int, int | None]] = []
    ioctl_references: list[int] = []
    registration_stores: list[Any] = []
    large_comparisons: list[tuple[int, Any]] = []
    for address, (_function, _high, body, ops) in surface.items():
        for match in re.finditer(
            r"MajorFunction\s*\[\s*([^\]]+)\s*\]", body, re.IGNORECASE
        ):
            expression = match.group(1).strip()
            try:
                index = int(expression, 0)
            except ValueError:
                index = None
            major_references.append((address, index))
        if re.search(r"\bIoControlCode\b", body, re.IGNORECASE):
            ioctl_references.append(address)
        for op in ops:
            mnemonic = str(op.getMnemonic())
            if mnemonic == "BRANCHIND":
                raise ValueError("dynamic IOCTL selection is unsupported")
            if mnemonic == "STORE" and op.getNumInputs() >= 3:
                constants = _dependency_constants(op.getInput(1).getDef())
                if 8 in constants and any(index in constants for index in range(28)):
                    registration_stores.append(op)
            if mnemonic in {"INT_EQUAL", "INT_NOTEQUAL"} and any(
                op.getInput(index).isConstant()
                and int(op.getInput(index).getOffset()) > 0xFFFF
                for index in range(op.getNumInputs())
            ):
                large_comparisons.append((address, op))
    if major_references != [(driver_address, 14)]:
        raise ValueError("complete surface contains another or dynamic MajorFunction reference")
    if registration_stores != [registration]:
        raise ValueError("complete surface contains another registration-shaped STORE")
    if ioctl_references != [handler_entry]:
        raise ValueError("IOCTL control reference exists outside the selected handler")
    if large_comparisons != [(handler_entry, comparison)]:
        raise ValueError("complete surface contains another or dynamic IOCTL comparison")
    _handler_function, _handler_high, handler_body, handler_ops = surface[handler_entry]
    if len(re.findall(r"\bIoControlCode\b", handler_body, re.IGNORECASE)) != 1:
        raise ValueError("selected handler has ambiguous IOCTL control references")
    comparisons = {
        str(op.getSeqnum())
        for op in handler_ops
        if str(op.getMnemonic())
        in {"INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL", "INT_SLESS", "INT_SLESSEQUAL"}
    }
    branches = {
        str(op.getSeqnum()) for op in handler_ops if str(op.getMnemonic()) == "CBRANCH"
    }
    expected_comparisons = {str(comparison.getSeqnum())} | {
        str(guard_comparison.getSeqnum())
        for guard_comparison, _guard_branch, _checked, _kinds in guards
    }
    expected_branches = {str(branch.getSeqnum())} | {
        str(guard_branch.getSeqnum())
        for _guard_comparison, guard_branch, _checked, _kinds in guards
    }
    if comparisons != expected_comparisons or branches != expected_branches:
        raise ValueError("selected handler contains unimplemented guard or IOCTL selection")
    if handler_address != handler_entry:
        raise ValueError("selected handler address changed during complete-surface audit")


def _one_op(operations: list[Any], label: str) -> Any:
    if len(operations) != 1:
        raise ValueError(f"{label} was not recovered")
    return operations[0]


def _dependency_constants(operation: Any, *, limit: int = 64) -> set[int]:
    constants: set[int] = set()
    pending = [operation] if operation is not None else []
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        sequence = str(current.getSeqnum())
        if sequence in visited:
            continue
        if len(visited) >= limit:
            raise ValueError("High-P-Code constant dependency graph is too large")
        visited.add(sequence)
        for index in range(current.getNumInputs()):
            node = current.getInput(index)
            if node.isConstant() or node.isAddress():
                constants.add(int(node.getOffset()))
            definition = node.getDef()
            if definition is not None:
                pending.append(definition)
    return constants


def _dependency_ops(operation: Any, *, limit: int = 64) -> list[Any]:
    pending = [operation]
    found: dict[str, Any] = {}
    while pending:
        current = pending.pop()
        sequence = str(current.getSeqnum())
        if sequence in found:
            continue
        if len(found) >= limit:
            raise ValueError("registration High-P-Code dependency graph is too large")
        found[sequence] = current
        for index in range(current.getNumInputs()):
            definition = current.getInput(index).getDef()
            if definition is not None:
                pending.append(definition)
    return list(found.values())


def _linear_source_path(operation: Any) -> list[Any]:
    reverse = []
    current = operation
    passthrough = {"CAST", "COPY", "INT_ZEXT", "SUBPIECE"}
    while True:
        reverse.append(current)
        mnemonic = str(current.getMnemonic())
        if mnemonic == "LOAD":
            break
        if mnemonic not in passthrough:
            raise ValueError("copy length High-P-Code definition is not a direct bounded chain")
        definitions = [
            current.getInput(index).getDef()
            for index in range(current.getNumInputs())
            if current.getInput(index).getDef() is not None
        ]
        if len(definitions) != 1 or len(reverse) >= 16:
            raise ValueError("copy length High-P-Code chain is ambiguous or too large")
        current = definitions[0]
    reverse.reverse()
    return reverse


def _direct_irp_system_buffer_offset(value_load: Any, program: Any) -> int:
    """Bind the selected length LOAD to x64 WDM arg2 RDX -> _IRP.SystemBuffer."""
    if str(value_load.getMnemonic()) != "LOAD" or value_load.getNumInputs() < 2:
        raise ValueError("SystemBuffer field source is not a High-P-Code LOAD")
    pointer_node = _strip_direct_passthrough(
        value_load.getInput(1), "SystemBuffer value address"
    )
    pointer_load = pointer_node.getDef()
    if (
        pointer_load is None
        or str(pointer_load.getMnemonic()) != "LOAD"
        or pointer_load.getNumInputs() < 2
    ):
        raise ValueError(
            "SystemBuffer length address must directly flow from one pointer LOAD"
        )
    irp_node = _strip_zero_offset_irp_address(pointer_load.getInput(1))
    if irp_node.getDef() is not None:
        raise ValueError(
            "IRP SystemBuffer address uses unsupported arithmetic or PHI: "
            f"{irp_node.getDef().getMnemonic()}"
        )
    if not bool(irp_node.isRegister()) or int(irp_node.getSize()) != 8:
        raise ValueError("IRP root is not the x64 WDM second parameter register")
    try:
        register = program.getRegister(irp_node.getAddress(), int(irp_node.getSize()))
    except TypeError:
        register = program.getRegister(irp_node.getAddress())
    if register is None or str(register.getName()).upper() != "RDX":
        raise ValueError("IRP root is not the x64 WDM second parameter RDX")
    _require_pdb_struct_field(program, "_IRP", "SystemBuffer", 0)
    return 0


def _strip_direct_passthrough(node: Any, label: str) -> Any:
    seen: set[str] = set()
    current = node
    while current.getDef() is not None:
        operation = current.getDef()
        mnemonic = str(operation.getMnemonic())
        if mnemonic not in {"CAST", "COPY"} or operation.getNumInputs() != 1:
            break
        sequence = str(operation.getSeqnum())
        if sequence in seen or len(seen) >= 8:
            raise ValueError(f"{label} passthrough is cyclic or too large")
        seen.add(sequence)
        current = operation.getInput(0)
    return current


def _strip_zero_offset_irp_address(node: Any) -> Any:
    current = _strip_direct_passthrough(node, "IRP argument")
    definition = current.getDef()
    if definition is None:
        return current
    if str(definition.getMnemonic()) != "PTRSUB" or definition.getNumInputs() != 2:
        return current
    offset = definition.getInput(1)
    if not bool(offset.isConstant()) or int(offset.getOffset()) != 0:
        raise ValueError("IRP SystemBuffer PTRSUB does not use exact PDB offset zero")
    return _strip_direct_passthrough(definition.getInput(0), "IRP argument")


def _require_pdb_struct_field(
    program: Any, structure_name: str, field_name: str, expected_offset: int
) -> None:
    structures = program.getDataTypeManager().getAllStructures()
    matches = []
    seen = 0
    while structures.hasNext():
        if seen >= cast(int, _CONFIG["max_pdb_structures"]):
            raise ValueError("PDB structure surface exceeds the configured cap")
        seen += 1
        structure = structures.next()
        if str(structure.getName()) != structure_name:
            continue
        fields = [
            component
            for component in structure.getComponents()
            if str(component.getFieldName()) == field_name
        ]
        if len(fields) == 1:
            matches.append(int(fields[0].getOffset()))
    if matches != [expected_offset]:
        raise ValueError(
            f"PDB {structure_name}.{field_name} is missing, ambiguous, or at the wrong offset"
        )


def _require_pdb_nested_field(
    program: Any,
    structure_name: str,
    path: tuple[tuple[str, int], ...],
    *,
    expected_offset: int,
) -> None:
    structures = program.getDataTypeManager().getAllStructures()
    roots = []
    seen = 0
    while structures.hasNext():
        if seen >= cast(int, _CONFIG["max_pdb_structures"]):
            raise ValueError("PDB structure surface exceeds the configured cap")
        seen += 1
        structure = structures.next()
        if str(structure.getName()) == structure_name:
            roots.append(structure)
    matches: list[int] = []
    for root in roots:
        current = root
        total = 0
        valid = True
        for index, (field_name, field_offset) in enumerate(path):
            components = [
                component
                for component in current.getComponents()
                if str(component.getFieldName()) == field_name
            ]
            if len(components) != 1 or int(components[0].getOffset()) != field_offset:
                valid = False
                break
            total += field_offset
            if index != len(path) - 1:
                current = components[0].getDataType()
                if not hasattr(current, "getComponents"):
                    valid = False
                    break
        if valid:
            matches.append(total)
    qualified = ".".join(name for name, _offset in path)
    if matches != [expected_offset]:
        raise ValueError(
            f"PDB {structure_name}.{qualified} is missing, ambiguous, or at the wrong offset"
        )


def _operation_ref(operation: Any, function: Any, image_base: int) -> dict[str, object]:
    sequence = operation.getSeqnum()
    function_rva = int(function.getEntryPoint().getOffset()) - image_base
    instruction_rva = int(sequence.getTarget().getOffset()) - image_base
    order = int(sequence.getTime())
    if function_rva <= 0 or instruction_rva <= 0 or not 0 <= order <= 65535:
        raise ValueError("High-P-Code operation has a noncanonical image-relative location")
    return {
        "function_rva": f"0x{function_rva:x}",
        "instruction_rva": f"0x{instruction_rva:x}",
        "pcode_order": order,
        "opcode": str(operation.getMnemonic()),
    }


def _dominates(high: Any, dominator_op: Any, sink_op: Any) -> bool:
    blocks = list(high.getBasicBlocks())
    by_index = {int(block.getIndex()): block for block in blocks}
    if len(by_index) != len(blocks) or not blocks:
        raise ValueError("High-P-Code CFG blocks are unavailable or ambiguous")
    entries = [block for block in blocks if int(block.getInSize()) == 0]
    if len(entries) != 1:
        raise ValueError("High-P-Code CFG entry is ambiguous")
    entry_index = int(entries[0].getIndex())
    all_indices = set(by_index)
    dominators = {
        index: ({index} if index == entry_index else set(all_indices)) for index in all_indices
    }
    changed = True
    while changed:
        changed = False
        for index, block in by_index.items():
            if index == entry_index:
                continue
            predecessors = [int(block.getIn(i).getIndex()) for i in range(block.getInSize())]
            if not predecessors or any(pred not in by_index for pred in predecessors):
                raise ValueError("High-P-Code CFG contains an unresolved predecessor")
            common = set.intersection(*(dominators[pred] for pred in predecessors))
            updated = {index} | common
            if updated != dominators[index]:
                dominators[index] = updated
                changed = True
    dominator_block = int(dominator_op.getParent().getIndex())
    sink_block = int(sink_op.getParent().getIndex())
    if dominator_block == sink_block:
        dominator_location = (
            int(dominator_op.getSeqnum().getTarget().getOffset()),
            int(dominator_op.getSeqnum().getTime()),
        )
        sink_location = (
            int(sink_op.getSeqnum().getTarget().getOffset()),
            int(sink_op.getSeqnum().getTime()),
        )
        return dominator_location < sink_location
    return dominator_block in dominators[sink_block]


def _ref_token(ref: dict[str, object]) -> str:
    return json.dumps(ref, sort_keys=True, separators=(",", ":"))


def _ref_key(ref: dict[str, object]) -> tuple[int, int, int, str]:
    return (
        int(str(ref["function_rva"]), 16),
        int(str(ref["instruction_rva"]), 16),
        cast(int, ref["pcode_order"]),
        str(ref["opcode"]),
    )


def _object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    return raw


def _list(raw: object, label: str) -> list[object]:
    if not isinstance(raw, list):
        raise ValueError(f"{label} must be an array")
    return raw


def _exact(raw: dict[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise ValueError(f"{label} fields mismatch")


def _integer(raw: object, label: str, low: int, high: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not low <= raw <= high:
        raise ValueError(f"{label} must be an integer in [{low}, {high}]")
    return raw


def _sha(raw: object, label: str) -> str:
    if not isinstance(raw, str) or _SHA256.fullmatch(raw) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return raw


def _rva(raw: object, label: str, *, allow_zero: bool = False) -> str:
    if not isinstance(raw, str) or _HEX.fullmatch(raw) is None or (len(raw) > 3 and raw[2] == "0"):
        raise ValueError(f"{label} must be canonical lowercase hexadecimal")
    value = int(raw, 16)
    if value > (1 << 64) - 1 or (not allow_zero and value == 0):
        raise ValueError(f"{label} must be a nonzero 64-bit RVA")
    return raw


def _text(raw: object, label: str, maximum: int) -> str:
    if (
        not isinstance(raw, str)
        or not raw
        or raw != raw.strip()
        or len(raw) > maximum
        or "\x00" in raw
    ):
        raise ValueError(f"{label} is invalid")
    return raw


def _enum(raw: object, allowed: set[str], label: str) -> str:
    if not isinstance(raw, str) or raw not in allowed:
        raise ValueError(f"{label} is unsupported")
    return raw
