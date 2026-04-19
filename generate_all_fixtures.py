"""
AI Sentinel — Multi-Format Test Fixture Generator
Generates scanner test fixtures across all major ML model file formats.

Every "malicious" payload is harmless (print/echo/marker file) but contains
the exact opcode patterns, structures, and embedded code that real attacks use.
Scanners SHOULD flag them. Safe files SHOULD pass clean.

Usage:
    python generate_all_fixtures.py
    python generate_all_fixtures.py --output-dir ./my-fixtures
"""

import os
import io
import sys
import json
import struct
import pickle
import zipfile
import tarfile
import argparse
import tempfile
import hashlib


# ============================================================================
# HELPERS
# ============================================================================

def write(path: str, data: bytes, desc: str):
    with open(path, "wb") as f:
        f.write(data)
    size = len(data)
    print(f"  {'✗' if 'malicious' in path or 'unsafe' in path else '✓'} {os.path.basename(path)} ({size:,} bytes) — {desc}")


# ============================================================================
# 1. PICKLE (.pkl) — The classic attack vector
# ============================================================================

def gen_pickle(out):
    """Standard pickle fixtures (protocol 0 and protocol 4)."""
    print("\n━━━ PICKLE (.pkl) ━━━")

    # Safe
    safe = pickle.dumps({"weights": [0.1, 0.2, 0.3], "config": {"layers": 3}}, protocol=2)
    write(f"{out}/safe-model.pkl", safe, "clean dict, no scanner should flag")

    # Malicious: os.system via classic GLOBAL opcode
    write(f"{out}/malicious-os-system.pkl",
          b"cos\nsystem\n(S'echo sentinel-pickle-os'\ntR.",
          "os.system() via GLOBAL + REDUCE")

    # Malicious: exec via __builtin__
    write(f"{out}/malicious-exec.pkl",
          b"c__builtin__\nexec\n(S'print(\"sentinel-exec\")'\ntR.",
          "__builtin__.exec via REDUCE")

    # Malicious: eval
    write(f"{out}/malicious-eval.pkl",
          b"c__builtin__\neval\n(S'1+1'\ntR.",
          "__builtin__.eval via REDUCE")

    # Malicious: subprocess
    write(f"{out}/malicious-subprocess.pkl",
          b"csubprocess\ncheck_output\n((S'echo'\nS'sentinel'\nltR.",
          "subprocess.check_output via REDUCE")

    # Malicious: protocol 4 STACK_GLOBAL (missed by ModelScan)
    write(f"{out}/malicious-stack-global.pkl",
          b"\x80\x04\x8c\x02os\x8c\x06system\x93\x8c\x1aecho sentinel-proto4\x85R.",
          "os.system via STACK_GLOBAL (protocol 4)")

    # Malicious: hidden inside normal dict
    write(f"{out}/malicious-hidden-in-dict.pkl",
          b"(dS'weights'\n(lS'1'\naS'2'\naS'hook'\ncos\nsystem\n(S'echo hidden'\ntRs.",
          "os.system hidden inside a normal dict")

    # Malicious: nt module (Windows bypass)
    write(f"{out}/malicious-nt-module.pkl",
          b"cnt\nsystem\n(S'echo sentinel-nt'\ntR.",
          "nt.system (Windows module bypass)")

    # Malicious: posix module
    write(f"{out}/malicious-posix-module.pkl",
          b"cposix\nsystem\n(S'echo sentinel-posix'\ntR.",
          "posix.system (alternative module bypass)")


# ============================================================================
# 2. PYTORCH (.pt / .pth) — Zip archives containing pickles
# ============================================================================

def gen_pytorch(out):
    """
    PyTorch .pt files are ZIP archives with pickle files inside.
    This tests whether scanners decompress before scanning.
    The pickle is at archive/data.pkl inside the zip.
    """
    print("\n━━━ PYTORCH (.pt / .pth) ━━━")

    # Safe: normal pytorch-style zip with clean pickle
    safe_data = pickle.dumps({"state_dict": {"layer1.weight": [0.1, 0.2], "layer1.bias": [0.01]}}, protocol=2)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", safe_data)
        zf.writestr("archive/version", "3")
    write(f"{out}/safe-model.pt", buf.getvalue(), "clean state_dict in zip archive")

    # Malicious: os.system hidden inside the zip's pickle
    mal_pickle = b"cos\nsystem\n(S'echo sentinel-pytorch'\ntR."
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", mal_pickle)
        zf.writestr("archive/version", "3")
    write(f"{out}/malicious-pytorch-os-system.pt", buf.getvalue(),
          "os.system inside zip/archive/data.pkl")

    # Malicious: exec payload inside pytorch zip
    mal_exec = b"c__builtin__\nexec\n(S'print(\"sentinel-pt-exec\")'\ntR."
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", mal_exec)
        zf.writestr("archive/version", "3")
    write(f"{out}/malicious-pytorch-exec.pt", buf.getvalue(),
          "exec inside zip/archive/data.pkl")

    # Malicious: protocol 4 inside pytorch zip
    mal_p4 = b"\x80\x04\x8c\x02os\x8c\x06system\x93\x8c\x14echo sentinel-pt-p4\x85R."
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", mal_p4)
        zf.writestr("archive/version", "3")
    write(f"{out}/malicious-pytorch-stack-global.pt", buf.getvalue(),
          "STACK_GLOBAL inside zip (protocol 4)")

    # Also generate .pth variant (same format, different extension)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", mal_pickle)
        zf.writestr("archive/version", "3")
    write(f"{out}/malicious-model.pth", buf.getvalue(),
          "same payload as .pt but with .pth extension")


# ============================================================================
# 3. JOBLIB (.joblib) — Pickle under the hood
# ============================================================================

def gen_joblib(out):
    """
    Joblib uses pickle (or zlib-compressed pickle) internally.
    The file starts with zlib magic or raw pickle bytes.
    """
    print("\n━━━ JOBLIB (.joblib) ━━━")

    # Safe: normal joblib (just compressed pickle of a dict)
    import zlib
    safe_pkl = pickle.dumps({"model": "sklearn_tree", "params": [1, 2, 3]}, protocol=2)
    # Joblib format: starts with zlib-compressed pickle
    safe_compressed = zlib.compress(safe_pkl)
    # Joblib header: NP\x01 (numpy array marker) or raw. We'll use raw pickle for simplicity.
    write(f"{out}/safe-model.joblib", safe_pkl, "clean pickle (joblib uses pickle internally)")

    # Malicious: os.system via pickle
    mal = b"cos\nsystem\n(S'echo sentinel-joblib'\ntR."
    write(f"{out}/malicious-model.joblib", mal,
          "os.system — scanners must check .joblib extension")

    # Malicious: compressed payload
    mal_compressed = zlib.compress(mal)
    # Prepend joblib's zlib marker (0x78 is zlib magic)
    write(f"{out}/malicious-compressed.joblib", mal_compressed,
          "zlib-compressed os.system — tests decompression before scan")


# ============================================================================
# 4. NUMPY (.npy / .npz) — allow_pickle vector
# ============================================================================

def gen_numpy(out):
    """
    .npy files with pickle objects embedded.
    When loaded with allow_pickle=True, the pickle executes.
    .npz is a zip of .npy files.
    """
    print("\n━━━ NUMPY (.npy / .npz) ━━━")

    # Safe: standard numeric numpy array
    # NPY format: magic + version + header + data
    # Magic: \x93NUMPY
    magic = b"\x93NUMPY"
    version = b"\x01\x00"  # version 1.0
    header = b"{'descr': '<f8', 'fortran_order': False, 'shape': (3,), }    \n"
    header_len = struct.pack("<H", len(header))
    data = struct.pack("<3d", 1.0, 2.0, 3.0)  # 3 float64 values
    safe_npy = magic + version + header_len + header + data
    write(f"{out}/safe-array.npy", safe_npy, "clean float64 array")

    # Malicious: object array containing pickle payload
    # NPY with object dtype triggers pickle deserialization
    obj_header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }     \n"
    obj_header_len = struct.pack("<H", len(obj_header))
    # The data section contains pickled objects
    mal_payload = b"cos\nsystem\n(S'echo sentinel-npy'\ntR."
    mal_npy = magic + version + obj_header_len + obj_header + mal_payload
    write(f"{out}/malicious-object-array.npy", mal_npy,
          "object dtype with pickle payload (allow_pickle=True vector)")

    # Malicious: .npz (zip of .npy files, one has payload)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("weights.npy", safe_npy)
        zf.writestr("hook.npy", mal_npy)
    write(f"{out}/malicious-archive.npz", buf.getvalue(),
          "npz with malicious .npy hidden alongside clean arrays")


# ============================================================================
# 5. KERAS / HDF5 (.h5 / .hdf5) — Lambda layer code injection
# ============================================================================

def gen_keras_h5(out):
    """
    Keras H5 files can contain Lambda layers with arbitrary Python code.
    We create a minimal HDF5-like structure with embedded code strings.
    
    Real HDF5 is complex binary, but scanners look for specific patterns:
    - Lambda layer definitions with Python code
    - model_config JSON with executable content
    """
    print("\n━━━ KERAS / HDF5 (.h5) ━━━")

    # HDF5 magic: \x89HDF\r\n\x1a\n
    h5_magic = b"\x89HDF\r\n\x1a\n"

    # Safe: model_config with normal layers
    safe_config = json.dumps({
        "class_name": "Sequential",
        "config": {
            "name": "safe_model",
            "layers": [
                {"class_name": "Dense", "config": {"units": 64, "activation": "relu"}},
                {"class_name": "Dense", "config": {"units": 10, "activation": "softmax"}}
            ]
        }
    }).encode()
    safe_h5 = h5_magic + b"\x00" * 512 + safe_config + b"\x00" * 256
    write(f"{out}/safe-model.h5", safe_h5, "clean Sequential model config")

    # Malicious: Lambda layer with embedded Python code
    mal_config = json.dumps({
        "class_name": "Sequential",
        "config": {
            "name": "malicious_model",
            "layers": [
                {"class_name": "Dense", "config": {"units": 64, "activation": "relu"}},
                {
                    "class_name": "Lambda",
                    "config": {
                        "function": "__import__('os').system('echo sentinel-h5-lambda')",
                        "function_type": "raw"
                    }
                },
                {"class_name": "Dense", "config": {"units": 10, "activation": "softmax"}}
            ]
        }
    }).encode()
    mal_h5 = h5_magic + b"\x00" * 512 + mal_config + b"\x00" * 256
    write(f"{out}/malicious-lambda-layer.h5", mal_h5,
          "Lambda layer with os.system in function field")

    # Malicious: eval in custom activation
    mal_eval_config = json.dumps({
        "class_name": "Sequential",
        "config": {
            "name": "eval_model",
            "layers": [
                {
                    "class_name": "Dense",
                    "config": {
                        "units": 64,
                        "activation": "lambda x: eval('__import__(\"os\").system(\"echo sentinel-h5-eval\")')"
                    }
                }
            ]
        }
    }).encode()
    mal_eval_h5 = h5_magic + b"\x00" * 512 + mal_eval_config + b"\x00" * 256
    write(f"{out}/malicious-eval-activation.h5", mal_eval_h5,
          "eval() in custom activation function string")

    # Also .hdf5 extension
    write(f"{out}/malicious-lambda.hdf5", mal_h5,
          "same Lambda payload with .hdf5 extension")


# ============================================================================
# 6. ONNX (.onnx) — Custom operator injection
# ============================================================================

def gen_onnx(out):
    """
    ONNX files are protobuf-serialized graphs. Malicious custom operators
    can embed arbitrary code. We create minimal protobuf structures with
    suspicious operator names and attributes that scanners should flag.
    """
    print("\n━━━ ONNX (.onnx) ━━━")

    # ONNX magic bytes (protobuf with specific field tags)
    # Field 1 (ir_version) = varint, Field 3 (graph) = length-delimited
    # Minimal valid-ish ONNX protobuf

    def make_onnx_bytes(graph_name: str, op_type: str, domain: str = ""):
        """Build minimal ONNX protobuf bytes."""
        # Encode strings as protobuf length-delimited fields
        def pb_string(field_num, s):
            tag = (field_num << 3) | 2
            encoded = s.encode()
            return bytes([tag]) + bytes([len(encoded)]) + encoded

        def pb_varint(field_num, val):
            tag = (field_num << 3) | 0
            return bytes([tag, val])

        # Build a node
        node = pb_string(4, op_type)  # field 4 = op_type
        if domain:
            node += pb_string(7, domain)  # field 7 = domain

        # Build graph
        graph = pb_string(1, graph_name)  # field 1 = name
        graph += bytes([(1 << 3) | 2, len(node)]) + node  # field 1 = node (repeated)

        # Build model
        model = pb_varint(1, 7)  # ir_version = 7
        model += pb_varint(2, 8)  # opset_import (simplified)
        model += bytes([(7 << 3) | 2, len(graph)]) + graph  # field 7 = graph

        return model

    # Safe: standard ONNX ops
    safe = make_onnx_bytes("safe_graph", "MatMul")
    write(f"{out}/safe-model.onnx", safe, "clean MatMul operator")

    # Malicious: suspicious custom operator that suggests code execution
    mal_exec = make_onnx_bytes("mal_graph", "PyExecute", "custom.exec")
    write(f"{out}/malicious-custom-exec-op.onnx", mal_exec,
          "custom PyExecute operator in custom.exec domain")

    # Malicious: operator name suggesting system call
    mal_sys = make_onnx_bytes("mal_graph", "SystemCall", "malicious.ops")
    write(f"{out}/malicious-system-call-op.onnx", mal_sys,
          "SystemCall operator in malicious domain")

    # Malicious: ONNX with embedded pickle bytes in attribute
    # Some frameworks store custom data as raw bytes attributes
    onnx_with_pickle = make_onnx_bytes("mal_graph", "CustomLayer", "")
    pickle_payload = b"cos\nsystem\n(S'echo sentinel-onnx'\ntR."
    onnx_with_pickle += bytes([(8 << 3) | 2, len(pickle_payload)]) + pickle_payload
    write(f"{out}/malicious-pickle-in-onnx.onnx", onnx_with_pickle,
          "pickle payload embedded as raw bytes attribute")


# ============================================================================
# 7. TFLITE (.tflite) — Malicious custom operators
# ============================================================================

def gen_tflite(out):
    """
    TFLite uses FlatBuffers format. Custom operators can contain
    arbitrary code. ModelAudit catches these; most other scanners don't.
    """
    print("\n━━━ TFLITE (.tflite) ━━━")

    # TFLite FlatBuffers files don't have a fixed magic number at offset 0
    # but the schema identifier is "TFL3" at offset 4-7 in the file identifier

    # Minimal FlatBuffer-ish structure
    # Real FlatBuffers have root table offset at byte 0-3, then file identifier
    # We'll create structures with embedded suspicious strings

    def make_tflite_bytes(operator_name: str, custom_code: str = ""):
        """Build minimal TFLite-like bytes with operator metadata."""
        # FlatBuffer root offset (placeholder)
        data = struct.pack("<I", 16)  # offset to root table
        data += b"TFL3"  # file identifier
        # Padding
        data += b"\x00" * 8
        # Embed operator name and custom code as searchable strings
        op_bytes = operator_name.encode() + b"\x00"
        data += struct.pack("<I", len(op_bytes)) + op_bytes
        if custom_code:
            code_bytes = custom_code.encode() + b"\x00"
            data += struct.pack("<I", len(code_bytes)) + code_bytes
        data += b"\x00" * 64  # padding
        return data

    # Safe
    safe = make_tflite_bytes("FULLY_CONNECTED")
    write(f"{out}/safe-model.tflite", safe, "clean FULLY_CONNECTED operator")

    # Malicious: custom op with code execution pattern
    mal = make_tflite_bytes(
        "CUSTOM_EXEC",
        "__import__('os').system('echo sentinel-tflite')"
    )
    write(f"{out}/malicious-custom-op.tflite", mal,
          "custom operator with os.system code string")

    # Malicious: FlexDelegate (known TFLite attack surface)
    mal_flex = make_tflite_bytes(
        "FlexDelegate",
        "exec(compile('import os; os.system(\"echo flex\")', '<string>', 'exec'))"
    )
    write(f"{out}/malicious-flex-delegate.tflite", mal_flex,
          "FlexDelegate with embedded exec/compile chain")


# ============================================================================
# 8. HUGGING FACE .bin — PyTorch weights with generic extension
# ============================================================================

def gen_hf_bin(out):
    """
    Hugging Face pytorch_model.bin files are standard PyTorch saves
    with a .bin extension. Tests whether scanners check .bin files.
    """
    print("\n━━━ HUGGING FACE (.bin) ━━━")

    # Safe: pytorch zip with .bin extension
    safe_pkl = pickle.dumps({"model.layer.weight": [0.1, 0.2]}, protocol=2)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", safe_pkl)
        zf.writestr("archive/version", "3")
    write(f"{out}/safe-pytorch_model.bin", buf.getvalue(),
          "clean pytorch weights with .bin extension")

    # Malicious: payload hidden under .bin extension
    mal_pkl = b"cos\nsystem\n(S'echo sentinel-hf-bin'\ntR."
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", mal_pkl)
        zf.writestr("archive/version", "3")
    write(f"{out}/malicious-pytorch_model.bin", buf.getvalue(),
          "os.system hidden in .bin (tests extension-agnostic scanning)")


# ============================================================================
# 9. SAFETENSORS (.safetensors) — Should ALWAYS be clean
# ============================================================================

def gen_safetensors(out):
    """
    Safetensors format cannot contain executable code by design.
    These are control samples — scanners should NEVER flag them.
    If a scanner flags a safetensors file, it's a false positive.
    """
    print("\n━━━ SAFETENSORS (.safetensors) — control samples ━━━")

    # Safetensors format: 8-byte LE header_size + JSON header + raw tensor data
    header = json.dumps({
        "__metadata__": {"format": "pt"},
        "weight": {"dtype": "F32", "shape": [3, 2], "data_offsets": [0, 24]}
    }).encode()
    header_size = struct.pack("<Q", len(header))
    tensor_data = struct.pack("<6f", 0.1, 0.2, 0.3, 0.4, 0.5, 0.6)
    safetensor = header_size + header + tensor_data
    write(f"{out}/safe-model.safetensors", safetensor,
          "valid safetensors — must NEVER be flagged (control sample)")

    # Adversarial: safetensors with suspicious strings in metadata
    # (should still NOT be flagged — metadata is not executable)
    header_sus = json.dumps({
        "__metadata__": {"format": "pt", "note": "os.system('echo this is just metadata')"},
        "weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}
    }).encode()
    header_size_sus = struct.pack("<Q", len(header_sus))
    tensor_data_sus = struct.pack("<2f", 0.1, 0.2)
    st_sus = header_size_sus + header_sus + tensor_data_sus
    write(f"{out}/safe-suspicious-metadata.safetensors", st_sus,
          "suspicious strings in metadata only — should NOT be flagged")


# ============================================================================
# 10. GGUF (.gguf) — llama.cpp quantized models
# ============================================================================

def gen_gguf(out):
    """
    GGUF format has a specific magic number and structured metadata.
    Growing attack surface as local LLM deployment increases.
    """
    print("\n━━━ GGUF (.gguf) ━━━")

    # GGUF magic: "GGUF" at offset 0, then version (uint32)
    GGUF_MAGIC = b"GGUF"

    # Safe: minimal GGUF header
    safe = GGUF_MAGIC
    safe += struct.pack("<I", 3)     # version 3
    safe += struct.pack("<Q", 0)     # tensor_count = 0
    safe += struct.pack("<Q", 1)     # metadata_kv_count = 1
    # One metadata entry: key="general.name", type=string(8), value="safe-model"
    key = b"general.name"
    safe += struct.pack("<Q", len(key)) + key
    safe += struct.pack("<I", 8)     # type = STRING
    val = b"safe-test-model"
    safe += struct.pack("<Q", len(val)) + val
    write(f"{out}/safe-model.gguf", safe, "clean minimal GGUF header")

    # Malicious: GGUF with suspicious metadata values
    mal = GGUF_MAGIC
    mal += struct.pack("<I", 3)
    mal += struct.pack("<Q", 0)
    mal += struct.pack("<Q", 1)
    key = b"general.description"
    mal += struct.pack("<Q", len(key)) + key
    mal += struct.pack("<I", 8)      # STRING type
    val = b"__import__('os').system('echo sentinel-gguf')"
    mal += struct.pack("<Q", len(val)) + val
    write(f"{out}/malicious-metadata.gguf", mal,
          "executable code string in GGUF metadata field")


# ============================================================================
# 11. DILL / CLOUDPICKLE — Extended pickle variants
# ============================================================================

def gen_dill_cloudpickle(out):
    """
    Dill and cloudpickle are pickle supersets that can serialize
    more Python objects (lambdas, closures, etc.). Same attack
    vectors as pickle but with additional dangerous capabilities.
    """
    print("\n━━━ DILL / CLOUDPICKLE (.dill / .cloudpickle) ━━━")

    # These use standard pickle protocol under the hood
    # The key test is whether scanners recognize these extensions

    # Malicious .dill
    mal = b"cos\nsystem\n(S'echo sentinel-dill'\ntR."
    write(f"{out}/malicious-model.dill", mal,
          "os.system — tests .dill extension recognition")

    # Malicious .cloudpickle
    write(f"{out}/malicious-model.cloudpickle", mal,
          "os.system — tests .cloudpickle extension recognition")

    # Malicious with dill-specific module reference
    mal_dill = b"cdill._dill\n_load_type\n(S'CodeType'\ntRp0\n."
    write(f"{out}/malicious-dill-codetype.dill", mal_dill,
          "dill._dill._load_type — dill-specific deserialization vector")


# ============================================================================
# 12. ZIP / TAR.GZ archives containing model files
# ============================================================================

def gen_archives(out):
    """
    Model archives that contain malicious files within them.
    Tests whether scanners recurse into archives.
    """
    print("\n━━━ ARCHIVES (.zip / .tar.gz) ━━━")

    mal_pickle = b"cos\nsystem\n(S'echo sentinel-archive'\ntR."
    safe_pickle = pickle.dumps({"w": [1, 2, 3]}, protocol=2)

    # Malicious zip: payload hidden among clean files
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("model/config.json", '{"model_type": "bert"}')
        zf.writestr("model/weights.pkl", safe_pickle)
        zf.writestr("model/tokenizer.pkl", mal_pickle)  # hidden payload
        zf.writestr("model/README.md", "# Safe model\nNothing to see here.")
    write(f"{out}/malicious-model-archive.zip", buf.getvalue(),
          "malicious pkl hidden among clean files in zip")

    # Malicious tar.gz
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        # Add clean config
        config_data = b'{"model_type": "gpt2"}'
        info = tarfile.TarInfo(name="model/config.json")
        info.size = len(config_data)
        tf.addfile(info, io.BytesIO(config_data))

        # Add malicious pickle
        info = tarfile.TarInfo(name="model/pytorch_model.bin")
        # Wrap in pytorch zip format
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as zf:
            zf.writestr("archive/data.pkl", mal_pickle)
        inner_bytes = inner_buf.getvalue()
        info.size = len(inner_bytes)
        tf.addfile(info, io.BytesIO(inner_bytes))

    write(f"{out}/malicious-model-archive.tar.gz", buf.getvalue(),
          "malicious pytorch_model.bin inside tar.gz")

    # Safe archive for false-positive control
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("model/config.json", '{"model_type": "bert"}')
        zf.writestr("model/weights.pkl", safe_pickle)
    write(f"{out}/safe-model-archive.zip", buf.getvalue(),
          "clean archive — should not be flagged")


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate multi-format ML model test fixtures for scanner validation"
    )
    parser.add_argument("--output-dir", "-o", default="./tests/fixtures",
                        help="Output directory (default: ./tests/fixtures)")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    gen_pickle(args.output_dir)
    gen_pytorch(args.output_dir)
    gen_joblib(args.output_dir)
    gen_numpy(args.output_dir)
    gen_keras_h5(args.output_dir)
    gen_onnx(args.output_dir)
    gen_tflite(args.output_dir)
    gen_hf_bin(args.output_dir)
    gen_safetensors(args.output_dir)
    gen_gguf(args.output_dir)
    gen_dill_cloudpickle(args.output_dir)
    gen_archives(args.output_dir)

    # Count totals
    all_files = os.listdir(args.output_dir)
    safe = [f for f in all_files if f.startswith("safe")]
    mal = [f for f in all_files if f.startswith("malicious") or f.startswith("unsafe")]

    print(f"\n{'━' * 60}")
    print(f"Generated {len(safe)} safe + {len(mal)} malicious fixtures")
    print(f"Total: {len(safe) + len(mal)} files in {args.output_dir}/")
    print(f"\nTest commands:")
    print(f"  modelscan --path {args.output_dir}/")
    print(f"  picklescan --path {args.output_dir}/")
    print(f"  modelaudit scan {args.output_dir}/")
    print(f"  veritensor scan {args.output_dir}/")
    print(f"\nExpected:")
    print(f"  • All 'safe-*' files: clean (0 findings)")
    print(f"  • All 'malicious-*' files: flagged (CRITICAL/HIGH)")
    print(f"  • Any scanner missing a malicious file has a blind spot")


if __name__ == "__main__":
    main()
