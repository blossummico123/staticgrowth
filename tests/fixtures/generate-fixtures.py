#!/usr/bin/env python3
"""
AI Sentinel — Test Fixture Generator

Generates model files with known vulnerabilities (and clean baselines)
so that scanners can be validated against ground truth.

Each fixture has a matching entry in expected-results.json that declares
whether each scanner should flag it and why.

Usage:
    python3 tests/fixtures/generate-fixtures.py
"""

import json
import os
import pickle
import struct
import sys

FIXTURES_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── Manifest: tracks every fixture with metadata ────────────────────────

manifest = []


def register(filename, *, malicious, category, description, techniques=None):
    """Register a fixture in the manifest."""
    manifest.append({
        "file": filename,
        "malicious": malicious,
        "category": category,
        "description": description,
        "techniques": techniques or [],
    })


# ─── Malicious Pickles ──────────────────────────────────────────────────

def make_malicious_eval():
    """Basic eval() payload — every scanner should catch this."""
    # pickle protocol 4: STACK_GLOBAL(builtins.eval) + REDUCE
    payload = (
        b'\x80\x04\x95\x62\x00\x00\x00\x00\x00\x00\x00'
        b'\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94'
        b'\x8c\x47__import__("builtins").print("AI Sentinel: malicious pickle detected")\x94'
        b'\x85\x94R\x94.'
    )
    path = os.path.join(FIXTURES_DIR, "malicious-pickle.pkl")
    with open(path, "wb") as f:
        f.write(payload)
    register("malicious-pickle.pkl",
             malicious=True,
             category="pickle-exploit",
             description="Calls builtins.eval() via STACK_GLOBAL + REDUCE",
             techniques=["STACK_GLOBAL", "REDUCE", "builtins.eval"])


def make_malicious_os_system():
    """os.system() payload — command execution."""

    class Exploit:
        def __reduce__(self):
            return (os.system, ("echo pwned",))

    path = os.path.join(FIXTURES_DIR, "malicious-os-system.pkl")
    with open(path, "wb") as f:
        pickle.dump(Exploit(), f, protocol=4)
    register("malicious-os-system.pkl",
             malicious=True,
             category="pickle-exploit",
             description="Calls os.system() via __reduce__",
             techniques=["__reduce__", "GLOBAL", "os.system"])


def make_malicious_subprocess():
    """subprocess.Popen payload — process spawning."""
    import subprocess

    class Exploit:
        def __reduce__(self):
            return (subprocess.Popen, (["echo", "pwned"],))

    path = os.path.join(FIXTURES_DIR, "malicious-subprocess.pkl")
    with open(path, "wb") as f:
        pickle.dump(Exploit(), f, protocol=4)
    register("malicious-subprocess.pkl",
             malicious=True,
             category="pickle-exploit",
             description="Calls subprocess.Popen via __reduce__",
             techniques=["__reduce__", "GLOBAL", "subprocess.Popen"])


def make_malicious_socket():
    """socket.socket payload — network access."""
    import socket

    class Exploit:
        def __reduce__(self):
            return (socket.socket, ())

    path = os.path.join(FIXTURES_DIR, "malicious-socket.pkl")
    with open(path, "wb") as f:
        pickle.dump(Exploit(), f, protocol=4)
    register("malicious-socket.pkl",
             malicious=True,
             category="pickle-exploit",
             description="Creates socket.socket via __reduce__",
             techniques=["__reduce__", "GLOBAL", "socket.socket"])


def make_malicious_exec():
    """exec() payload — arbitrary code execution with multi-line code."""

    class Exploit:
        def __reduce__(self):
            return (exec, ("import os; os.makedirs('/tmp/pwned', exist_ok=True)",))

    path = os.path.join(FIXTURES_DIR, "malicious-exec.pkl")
    with open(path, "wb") as f:
        pickle.dump(Exploit(), f, protocol=4)
    register("malicious-exec.pkl",
             malicious=True,
             category="pickle-exploit",
             description="Calls builtins.exec() with compound statement via __reduce__",
             techniques=["__reduce__", "GLOBAL", "builtins.exec"])


def make_malicious_nested():
    """Nested payload — dangerous callable wrapped in benign container."""

    class Inner:
        def __reduce__(self):
            return (os.system, ("echo inner-pwned",))

    path = os.path.join(FIXTURES_DIR, "malicious-nested.pkl")
    with open(path, "wb") as f:
        pickle.dump({"config": {"debug": True}, "hook": Inner()}, f, protocol=4)
    register("malicious-nested.pkl",
             malicious=True,
             category="pickle-exploit",
             description="os.system() hidden inside nested dict structure",
             techniques=["__reduce__", "GLOBAL", "os.system", "nested-container"])


def make_malicious_getattr_chain():
    """getattr chain — uses apply_key trick to call dangerous functions indirectly."""
    # Builds: getattr(__import__('os'), 'system')('echo pwned')
    # Using raw pickle opcodes for the import+getattr pattern
    payload = (
        b'\x80\x04\x95\x30\x00\x00\x00\x00\x00\x00\x00'
        b'\x8c\x08builtins\x94\x8c\x0a__import__\x94\x93\x94'
        b'\x8c\x02os\x94\x85\x94R\x94'
        b'\x8c\x06system\x94\x86\x94R\x94.'
    )
    # Simpler version that scanners should still flag: uses builtins.__import__
    class Exploit:
        def __reduce__(self):
            return (__builtins__.__import__ if isinstance(__builtins__, type(os)) else __builtins__["__import__"],
                    ("os",))

    path = os.path.join(FIXTURES_DIR, "malicious-import.pkl")
    with open(path, "wb") as f:
        pickle.dump(Exploit(), f, protocol=4)
    register("malicious-import.pkl",
             malicious=True,
             category="pickle-exploit",
             description="Calls builtins.__import__('os') via __reduce__",
             techniques=["__reduce__", "GLOBAL", "builtins.__import__"])


def make_malicious_webbrowser():
    """webbrowser.open — less obvious dangerous module."""
    import webbrowser

    class Exploit:
        def __reduce__(self):
            return (webbrowser.open, ("http://evil.example.com",))

    path = os.path.join(FIXTURES_DIR, "malicious-webbrowser.pkl")
    with open(path, "wb") as f:
        pickle.dump(Exploit(), f, protocol=4)
    register("malicious-webbrowser.pkl",
             malicious=True,
             category="pickle-exploit",
             description="Opens URL via webbrowser.open — exfiltration vector",
             techniques=["__reduce__", "GLOBAL", "webbrowser.open"])


# ─── Safe Pickles ────────────────────────────────────────────────────────

def make_safe_model_pt():
    """Clean PyTorch-style state dict — no dangerous opcodes."""
    data = {
        "model_state_dict": {
            "layer1.weight": [0.1, 0.2, 0.3, 0.4],
            "layer1.bias": [0.0, 0.0],
            "layer2.weight": [0.5, 0.6],
            "layer2.bias": [0.0],
        },
        "optimizer_state_dict": {},
        "epoch": 1,
        "loss": 0.5,
    }
    path = os.path.join(FIXTURES_DIR, "safe-model.pt")
    with open(path, "wb") as f:
        pickle.dump(data, f, protocol=4)
    register("safe-model.pt",
             malicious=False,
             category="clean-pickle",
             description="Standard PyTorch state dict with only safe builtins")


def make_safe_sklearn_style():
    """Clean sklearn-style model — uses numpy arrays but no dangerous calls."""
    data = {
        "coef_": [0.1, -0.2, 0.3],
        "intercept_": 0.5,
        "classes_": [0, 1],
        "n_features_in_": 3,
    }
    path = os.path.join(FIXTURES_DIR, "safe-sklearn.pkl")
    with open(path, "wb") as f:
        pickle.dump(data, f, protocol=4)
    register("safe-sklearn.pkl",
             malicious=False,
             category="clean-pickle",
             description="Sklearn-style model dict with only safe builtins")


def make_safe_config():
    """Clean config pickle — plain data structures only."""
    data = {
        "model_name": "bert-base-uncased",
        "max_length": 512,
        "batch_size": 32,
        "learning_rate": 2e-5,
        "labels": ["positive", "negative", "neutral"],
    }
    path = os.path.join(FIXTURES_DIR, "safe-config.pkl")
    with open(path, "wb") as f:
        pickle.dump(data, f, protocol=4)
    register("safe-config.pkl",
             malicious=False,
             category="clean-pickle",
             description="Plain config dict — no code execution possible")


def make_safe_numpy_style():
    """Mimics numpy array serialization structure without requiring numpy."""
    # numpy arrays in pickle use _reconstruct + GLOBAL for numpy.core.multiarray
    # We just store raw lists to keep it safe and dependency-free
    data = {
        "weights": [[0.1, 0.2], [0.3, 0.4], [0.5, 0.6]],
        "biases": [0.01, 0.02, 0.03],
        "shape": (3, 2),
        "dtype": "float32",
    }
    path = os.path.join(FIXTURES_DIR, "safe-numpy-style.pkl")
    with open(path, "wb") as f:
        pickle.dump(data, f, protocol=4)
    register("safe-numpy-style.pkl",
             malicious=False,
             category="clean-pickle",
             description="Weight matrix as plain lists — no numpy dependency")


# ─── Safe Non-Pickle Formats ────────────────────────────────────────────

def make_safe_safetensors():
    """Minimal valid safetensors file — header-only, no tensors.

    Safetensors format:
    - 8 bytes: little-endian u64 header size
    - N bytes: JSON header (tensor metadata)
    - remaining: tensor data
    """
    header = json.dumps({
        "__metadata__": {
            "format": "pt",
            "description": "AI Sentinel test fixture — clean safetensors file",
        }
    }).encode("utf-8")
    path = os.path.join(FIXTURES_DIR, "safe-model.safetensors")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(header)))
        f.write(header)
    register("safe-model.safetensors",
             malicious=False,
             category="clean-safetensors",
             description="Valid safetensors with metadata-only header — inherently safe format")


def make_safe_onnx():
    """Minimal ONNX file stub.

    ONNX uses protobuf. We write a minimal valid protobuf with just the
    ir_version and opset_import fields. This is enough for scanners to
    recognize the format without requiring the onnx package.
    """
    # Minimal protobuf for onnx.ModelProto:
    #   field 1 (ir_version): varint 8
    #   field 8 (opset_import): embedded message with field 2 (version) = 17
    proto = (
        b'\x08\x08'          # ir_version = 8
        b'\x42\x03'          # opset_import (field 8, wire type 2, length 3)
        b'\x10\x11\x00'      # version = 17 (inside opset_import)
    )
    path = os.path.join(FIXTURES_DIR, "safe-model.onnx")
    with open(path, "wb") as f:
        f.write(proto)
    register("safe-model.onnx",
             malicious=False,
             category="clean-onnx",
             description="Minimal valid ONNX protobuf — no executable content")


def make_safe_h5():
    """Minimal HDF5 file signature.

    HDF5 files start with the 8-byte signature \\x89HDF\\r\\n\\x1a\\n.
    We write just the superblock to create a recognizable-but-empty file.
    Full HDF5 creation would require h5py.
    """
    # HDF5 signature + minimal superblock (version 0)
    signature = b'\x89HDF\r\n\x1a\n'
    # Superblock version 0 fields (simplified)
    superblock = (
        b'\x00'  # version of superblock
        b'\x00'  # version of file free-space storage
        b'\x00'  # version of root group symbol table entry
        b'\x00'  # reserved
        b'\x00'  # version of shared header message format
        b'\x08'  # size of offsets (8 bytes)
        b'\x08'  # size of lengths (8 bytes)
        b'\x00'  # reserved
    )
    path = os.path.join(FIXTURES_DIR, "safe-model.h5")
    with open(path, "wb") as f:
        f.write(signature)
        f.write(superblock)
        f.write(b'\x00' * 64)  # padding
    register("safe-model.h5",
             malicious=False,
             category="clean-hdf5",
             description="Minimal HDF5 with valid signature — no Lambda layers")


# ─── Generate everything ─────────────────────────────────────────────────

def main():
    print("Generating AI Sentinel test fixtures...")
    print()

    # Malicious fixtures
    make_malicious_eval()
    make_malicious_os_system()
    make_malicious_subprocess()
    make_malicious_socket()
    make_malicious_exec()
    make_malicious_nested()
    make_malicious_getattr_chain()
    make_malicious_webbrowser()

    # Safe fixtures
    make_safe_model_pt()
    make_safe_sklearn_style()
    make_safe_config()
    make_safe_numpy_style()
    make_safe_safetensors()
    make_safe_onnx()
    make_safe_h5()

    # Write manifest
    manifest_path = os.path.join(FIXTURES_DIR, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    malicious_count = sum(1 for m in manifest if m["malicious"])
    safe_count = sum(1 for m in manifest if not m["malicious"])

    print(f"  Generated {malicious_count} malicious fixtures:")
    for m in manifest:
        if m["malicious"]:
            print(f"    - {m['file']}: {m['description']}")

    print()
    print(f"  Generated {safe_count} safe fixtures:")
    for m in manifest:
        if not m["malicious"]:
            print(f"    - {m['file']}: {m['description']}")

    print()
    print(f"  Manifest → {manifest_path}")
    print(f"  Total: {len(manifest)} fixtures")


if __name__ == "__main__":
    main()
