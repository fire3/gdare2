from __future__ import annotations

from gdare2 import registry


def _target(tmp_path):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x90\xc3")
    return str(target)


def test_instance_id_ignores_runtime_options(tmp_path):
    target = _target(tmp_path)
    import_options = {
        "arch": "x86",
        "bits": "64",
        "base": "0x400000",
        "endian": "little",
        "ghidra_language": None,
        "compiler": None,
        "loader": None,
        "loader_args": [],
        "force_language": False,
        "force_base": False,
        "no_analysis": False,
    }
    base = registry.instance_id(target, import_options=import_options)
    with_analyze = registry.instance_id(
        target, import_options={**import_options, "analyze": 2}
    )
    with_runtime = registry.instance_id(
        target,
        import_options={
            **import_options,
            "analyze": 2,
            "reimport": True,
            "ephemeral": True,
            "readonly": True,
        },
    )
    assert base == with_analyze == with_runtime


def test_instance_id_tracks_import_options(tmp_path):
    target = _target(tmp_path)
    x86 = registry.instance_id(
        target,
        import_options={"arch": "x86", "bits": "64", "base": "0x400000"},
    )
    arm = registry.instance_id(
        target,
        import_options={"arch": "arm", "bits": "32", "base": "0x400000"},
    )
    assert x86 != arm


def test_project_name_is_stable(tmp_path):
    name = registry.project_name("/tmp/hello world.bin", "0123456789abcdef")
    assert name == "hello_world.bin-01234567"
