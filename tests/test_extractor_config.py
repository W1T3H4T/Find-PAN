"""Per-platform extractor configuration: sections, ordered candidates, cwd and path placeholders."""

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from find_pan import archives, config
from find_pan.errors import ConfigError, ExtractorUnavailable

LOGGER = logging.getLogger("test.extractor_config")
ROOT = Path(__file__).resolve().parents[1]
SHIPPED = ROOT / "config" / "find-pan-conf.yaml"


# --- platform keys ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("system, expected", [
    ("win32", "windows"), ("cygwin", "windows"), ("linux", "linux"), ("darwin", "macos"),
    ("freebsd13", "other"), ("sunos5", "other"),
])
def test_platform_key(system, expected):
    assert config.platform_key(system) == expected


def test_platform_key_defaults_to_the_running_system():
    assert config.platform_key() == config.platform_key(sys.platform)


# --- resolving an entry to candidates -----------------------------------------------------------------------------------


def candidate(command, **extra):
    return {"command": command, "args": ["{archive}"], **extra}


def test_a_flat_entry_is_a_single_candidate_on_every_platform():
    entry = {"command": "tar", "args": ["-xf", "{archive}"], "copy_archive_to_tempdir": False}
    for platform in ("windows", "linux", "macos", "other"):
        assert config.extractor_candidates(entry, platform) == [entry]


def test_the_exact_platform_section_wins_over_posix_and_flat_keys():
    entry = {"command": "flat", "args": ["x"], "linux": candidate("linux-tool"), "posix": candidate("posix-tool")}
    assert [c["command"] for c in config.extractor_candidates(entry, "linux")] == ["linux-tool"]


def test_posix_covers_every_non_windows_platform_without_its_own_section():
    entry = {"windows": candidate("win-tool"), "posix": candidate("posix-tool")}
    for platform in ("linux", "macos", "other"):
        assert [c["command"] for c in config.extractor_candidates(entry, platform)] == ["posix-tool"]


def test_windows_never_falls_back_to_posix():
    entry = {"posix": candidate("posix-tool")}
    assert config.extractor_candidates(entry, "windows") == []


def test_a_section_may_be_a_list_and_keeps_its_order():
    entry = {"windows": [candidate("first"), candidate("second"), candidate("third")]}
    assert [c["command"] for c in config.extractor_candidates(entry, "windows")] == ["first", "second", "third"]


def test_entry_level_settings_are_defaults_for_every_candidate():
    entry = {"copy_archive_to_tempdir": True, "max_files": 7, "compression": ["deflate"],
             "posix": [candidate("a"), candidate("b", copy_archive_to_tempdir=False)]}
    first, second = config.extractor_candidates(entry, "linux")
    assert first["copy_archive_to_tempdir"] is True and first["max_files"] == 7
    assert second["copy_archive_to_tempdir"] is False and second["max_files"] == 7
    assert "linux" not in first and "posix" not in first and "windows" not in first


def test_an_entry_with_nothing_for_this_platform_has_no_candidates():
    assert config.extractor_candidates({"windows": candidate("x")}, "linux") == []
    assert config.extractor_candidates({}, "linux") == []


# --- validation ------------------------------------------------------------------------------------------------------------------


def write_config(tmp_path, extractors):
    path = tmp_path / "conf.yaml"
    path.write_text(yaml.safe_dump({"extractors": extractors}), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("bad", [
    {"tar": {"windows": {"args": ["x"]}}},                                      # no command
    {"tar": {"windows": {"command": "t", "args": "not-a-list"}}},                # args not a list
    {"tar": {"windows": {"command": "t", "args": [1, 2]}}},                      # args not strings
    {"tar": {"windows": {"command": "t", "args": ["x"], "cwd": "elsewhere"}}},   # unknown cwd
    {"tar": {"posix": [candidate("ok"), "oops"]}},                               # candidate not a mapping
    {"tar": {"windows": 5}},                                                     # section not a mapping/list
    {"tar": "not-a-mapping"},
])
def test_invalid_extractor_configuration_is_a_config_error(tmp_path, bad):
    with pytest.raises(ConfigError):
        config.load_extractor_config(write_config(tmp_path, bad))


def test_platform_sections_and_flat_entries_both_load(tmp_path):
    loaded = config.load_extractor_config(write_config(tmp_path, {
        "tar": {"windows": [candidate("a")], "posix": candidate("b"), "compression": ["store"]},
        "zip": {"command": "unzip", "args": ["{archive}"]},
    }))
    assert set(loaded) == {"tar", "zip"} and loaded["zip"]["command"] == "unzip"


def test_an_empty_args_list_is_allowed_to_load_but_is_not_usable(tmp_path):
    """Kept loadable so a half-edited file reports 'incomplete' at use rather than refusing to start."""
    loaded = config.load_extractor_config(write_config(tmp_path, {"tar": {"command": "tar", "args": []}}))
    assert loaded["tar"]["args"] == []


# --- shipped defaults -----------------------------------------------------------------------------------------------------------


def test_defaults_cover_every_archive_type_on_windows_and_posix():
    for archive_type in ("tar", "zip", "7z", "gzip"):
        entry = config.DEFAULT_EXTRACTORS[archive_type]
        assert config.extractor_candidates(entry, "windows"), archive_type
        assert config.extractor_candidates(entry, "linux"), archive_type
        assert config.extractor_candidates(entry, "macos"), archive_type


def test_the_windows_tar_candidates_name_each_tar_build_with_its_own_arguments():
    candidates = config.extractor_candidates(config.DEFAULT_EXTRACTORS["tar"], "windows")
    commands = [c["command"].lower() for c in candidates]
    assert commands[0].endswith(r"system32\tar.exe")                         # bsdtar first: no quirks
    assert any(r"git\usr\bin\tar.exe" in c for c in commands)                # MSYS GNU tar
    assert any(r"gnuwin32\bin\tar.exe" in c for c in commands)               # native GNU tar 1.13
    gnu = [c for c in candidates if "--force-local" in c["args"]]
    assert gnu and all(c["cwd"] == "tempdir" and "{archive_posix}" in c["args"] for c in gnu)
    assert "--force-local" not in candidates[0]["args"] and "cwd" not in candidates[0]


def test_build_extractor_config_writes_the_defaults(tmp_path):
    path = tmp_path / "conf.yaml"
    config.build_extractor_config(str(path))
    assert config.load_extractor_config(str(path)) == config.DEFAULT_EXTRACTORS
    assert config.load_extraction_limits(str(path)) == config.ExtractionLimits()


def test_the_shipped_configuration_file_equals_the_defaults():
    """config/find-pan-conf.yaml and the built-in defaults must not drift apart."""
    assert config.load_extractor_config(str(SHIPPED)) == config.DEFAULT_EXTRACTORS


# --- choosing and running a candidate -----------------------------------------------------------------------------------------------


class Runner:
    def __init__(self):
        self.commands = []

    def __call__(self, cmd, check, capture_output, text):
        self.commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")


@pytest.fixture
def archive(tmp_path):
    path = tmp_path / "data.zip"
    path.write_bytes(b"x")
    return str(path)


def extract(archive, entry, runner=None, platform="linux", **kwargs):
    runner = runner or Runner()
    with archives.extract_archive(archive, {"zip": entry}, LOGGER, archive_type="zip", runner=runner,
                                  **kwargs) as directory:
        pass
    return runner, directory


def test_the_first_candidate_that_exists_is_used(archive, monkeypatch):
    monkeypatch.setattr(config, "platform_key", lambda system=None: "linux")
    available = {"second-tool": "/opt/second-tool", "third-tool": "/opt/third-tool"}
    monkeypatch.setattr(archives.shutil, "which", lambda command: available.get(command))
    entry = {"linux": [candidate("first-tool"), candidate("second-tool"), candidate("third-tool")]}
    runner, _ = extract(archive, entry)
    assert runner.commands[0][0] == "/opt/second-tool"


def test_when_no_candidate_exists_the_error_lists_every_command_tried(archive, monkeypatch):
    monkeypatch.setattr(config, "platform_key", lambda system=None: "linux")
    monkeypatch.setattr(archives.shutil, "which", lambda command: None)

    class Missing(Runner):
        def __call__(self, *args, **kwargs):
            raise FileNotFoundError("no such tool")

    entry = {"linux": [candidate("alpha-tool"), candidate("beta-tool")]}
    with pytest.raises(ExtractorUnavailable) as info:
        extract(archive, entry, Missing())
    assert "alpha-tool" in str(info.value) and "beta-tool" in str(info.value)


def test_an_entry_with_nothing_for_this_platform_is_unavailable(archive, monkeypatch):
    monkeypatch.setattr(config, "platform_key", lambda system=None: "linux")
    with pytest.raises(ExtractorUnavailable, match="linux"):
        extract(archive, {"windows": candidate("only-on-windows")})


def test_incomplete_candidates_are_skipped_and_all_incomplete_is_unavailable(archive, monkeypatch):
    monkeypatch.setattr(config, "platform_key", lambda system=None: "linux")
    with pytest.raises(ExtractorUnavailable, match="Incomplete"):
        extract(archive, {"linux": [{"command": "x", "args": []}, {"args": ["{archive}"]}]})


def test_the_selected_platform_follows_platform_key(archive, monkeypatch):
    monkeypatch.setattr(archives.shutil, "which", lambda command: command)
    entry = {"windows": candidate("win-tool"), "posix": candidate("posix-tool")}
    monkeypatch.setattr(config, "platform_key", lambda system=None: "windows")
    assert extract(archive, entry)[0].commands[0][0] == "win-tool"
    monkeypatch.setattr(config, "platform_key", lambda system=None: "macos")
    assert extract(archive, entry)[0].commands[0][0] == "posix-tool"


def test_posix_placeholders_are_forward_slash_paths(archive, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "platform_key", lambda system=None: "linux")
    monkeypatch.setattr(archives.shutil, "which", lambda command: command)
    entry = {"linux": {"command": "t", "args": ["{archive_posix}", "{tempdir_posix}", "{archive}", "{tempdir}"]}}
    runner, directory = extract(archive, entry)
    archive_posix, tempdir_posix, archive_native, tempdir_native = runner.commands[0][1:]
    assert archive_posix == os.path.abspath(archive).replace("\\", "/")
    assert tempdir_posix == directory.replace("\\", "/")
    assert archive_native == os.path.abspath(archive) and tempdir_native == directory


def test_cwd_tempdir_runs_the_tool_inside_the_extraction_directory(archive, monkeypatch):
    monkeypatch.setattr(config, "platform_key", lambda system=None: "linux")
    monkeypatch.setattr(archives.shutil, "which", lambda command: command)
    seen = []

    def fake_run_limited(cmd, directory, limits, cwd=None):
        seen.append((directory, cwd))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(archives, "run_limited", fake_run_limited)
    for cwd, expect_inside in (("tempdir", True), (None, False)):
        seen.clear()
        entry = {"linux": candidate("t", **({"cwd": cwd} if cwd else {}))}
        with archives.extract_archive(archive, {"zip": entry}, LOGGER, archive_type="zip") as directory:
            pass
        assert seen == [(directory, directory if expect_inside else None)]


def test_environment_variables_in_the_command_are_expanded(archive, monkeypatch, tmp_path):
    tool = tmp_path / "mytool"
    tool.write_text("", encoding="utf-8")
    monkeypatch.setenv("FIND_PAN_TOOL_DIR", str(tmp_path))
    variable = "%FIND_PAN_TOOL_DIR%" if sys.platform == "win32" else "$FIND_PAN_TOOL_DIR"
    monkeypatch.setattr(config, "platform_key", lambda system=None: "linux")
    monkeypatch.setattr(archives.shutil, "which", lambda command: command if os.path.isfile(command) else None)
    runner, _ = extract(archive, {"linux": candidate(variable + os.sep + "mytool")})
    assert runner.commands[0][0] == str(tool)


def test_per_candidate_limits_override_the_global_ones(archive, monkeypatch):
    monkeypatch.setattr(config, "platform_key", lambda system=None: "linux")
    monkeypatch.setattr(archives.shutil, "which", lambda command: command)
    captured = []

    def fake_run_limited(cmd, directory, limits, cwd=None):
        captured.append(limits.max_files)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(archives, "run_limited", fake_run_limited)
    entry = {"max_files": 11, "linux": [candidate("a", max_files=22)]}
    with archives.extract_archive(archive, {"zip": entry}, LOGGER, archive_type="zip"):
        pass
    assert captured == [22]


def test_the_built_in_gnu_tar_guesswork_is_gone():
    """Per-platform candidates replace the detection that rewrote tar arguments in code."""
    assert not hasattr(archives, "_is_gnu_tar") and not hasattr(archives, "_needs_force_local")


# --- upgrading a configuration generated by an earlier find-pan --------------------------------------------------------


LEGACY_FLAT = {
    "limits": {"max_files": 100000},
    "extractors": {
        "tar": {"command": "tar", "args": ["-xf", "{archive}", "-C", "{tempdir}"], "copy_archive_to_tempdir": False},
        "zip": {"command": "unzip", "args": ["{archive}", "-d", "{tempdir}"]},
    },
}


@pytest.fixture
def user_config(tmp_path, monkeypatch):
    """A user-level config directory (XDG_CONFIG_HOME) and an empty application root."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(config, "_application_root", lambda: str(tmp_path / "app"))
    directory = tmp_path / "xdg" / "find-pan"
    directory.mkdir(parents=True)
    return directory / "find-pan-conf.yaml"


def test_a_legacy_user_config_is_backed_up_and_replaced_with_the_defaults(user_config, caplog):
    user_config.write_text(yaml.safe_dump(LEGACY_FLAT), encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="find_pan.config"):
        path = config.find_extractor_config_path()
    assert path == str(user_config)
    assert config.load_extractor_config(path) == config.DEFAULT_EXTRACTORS
    backup = user_config.with_name(user_config.name + ".legacy")
    assert yaml.safe_load(backup.read_text(encoding="utf-8")) == LEGACY_FLAT
    assert str(backup) in caplog.text and "legacy" in caplog.text.lower()


def test_an_existing_backup_is_never_overwritten(user_config):
    first = user_config.with_name(user_config.name + ".legacy")
    first.write_text("older backup", encoding="utf-8")
    user_config.write_text(yaml.safe_dump(LEGACY_FLAT), encoding="utf-8")
    config.find_extractor_config_path()
    assert first.read_text(encoding="utf-8") == "older backup"
    assert len(list(user_config.parent.glob("find-pan-conf.yaml.legacy*"))) == 2


def test_a_current_config_is_left_untouched(user_config):
    config.build_extractor_config(str(user_config))
    before = user_config.read_bytes()
    assert config.find_extractor_config_path() == str(user_config)
    assert user_config.read_bytes() == before
    assert not list(user_config.parent.glob("*.legacy*"))


def test_a_hand_written_config_with_platform_sections_is_not_legacy(user_config):
    custom = {"extractors": {"tar": {"linux": {"command": "mytar", "args": ["{archive}"]}}}}
    user_config.write_text(yaml.safe_dump(custom), encoding="utf-8")
    config.find_extractor_config_path()
    assert yaml.safe_load(user_config.read_text(encoding="utf-8")) == custom
    assert not list(user_config.parent.glob("*.legacy*"))


def test_the_application_root_config_is_never_rewritten(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty-xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "empty-home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "empty-home"))
    app_config = tmp_path / "app" / "config" / "find-pan-conf.yaml"
    app_config.parent.mkdir(parents=True)
    app_config.write_text(yaml.safe_dump(LEGACY_FLAT), encoding="utf-8")
    monkeypatch.setattr(config, "_application_root", lambda: str(tmp_path / "app"))
    assert config.find_extractor_config_path() == str(app_config)
    assert yaml.safe_load(app_config.read_text(encoding="utf-8")) == LEGACY_FLAT


def test_generated_and_shipped_configs_carry_the_schema_marker(tmp_path):
    path = tmp_path / "conf.yaml"
    config.build_extractor_config(str(path))
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["schema"] == config.SCHEMA_VERSION
    assert yaml.safe_load(SHIPPED.read_text(encoding="utf-8"))["schema"] == config.SCHEMA_VERSION
