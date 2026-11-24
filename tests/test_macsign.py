from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import macsign
from macsign import AD_HOC, App, Failure, Identity, Shell

RELEASE = Identity("A" * 40, "Developer ID Application: Jane Citizen (TEAMID1234)")
RENEWED = Identity("B" * 40, RELEASE.name)
DEVELOPMENT = Identity("C" * 40, "Apple Development: Jane Citizen (PERSON1234)")


def find_identity_output(*identities: Identity) -> str:
    lines = [f'  {n}) {i.sha1} "{i.name}"' for n, i in enumerate(identities, 1)]
    return "\n".join([*lines, f"     {len(identities)} valid identities found", ""])


class FakeShell(Shell):
    """Records commands. Answers come from a list of (text in the command, exit code, stdout, stderr)."""

    def __init__(self, *answers: tuple[str, int, str, str], dry_run: bool = False) -> None:
        super().__init__(dry_run)
        self.answers = answers
        self.commands: list[str] = []

    def read(self, *cmd: macsign.Arg, stdin: str = "") -> subprocess.CompletedProcess[str]:
        line = " ".join(map(str, cmd))
        self.commands.append(line)
        for text, code, out, err in self.answers:
            if text in line:
                return subprocess.CompletedProcess(line, code, out, err)
        if "find-generic-password" in line:
            return subprocess.CompletedProcess(line, 44, "", "not found")
        return subprocess.CompletedProcess(line, 0, "", "")

    def run_live(self, *cmd: macsign.Arg, interactive: bool = False) -> bool:
        return self.read(*cmd).returncode == 0

    def run_json(self, *cmd: macsign.Arg) -> dict[str, Any]:
        return json.loads(self.read(*cmd).stdout or "{}")


class TempDirCase(unittest.TestCase):
    def setUp(self) -> None:
        self.output = io.StringIO()
        for redirect in (contextlib.redirect_stdout, contextlib.redirect_stderr):
            context = redirect(self.output)
            context.__enter__()
            self.addCleanup(context.__exit__, None, None, None)
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.dir = Path(folder.name).resolve()
        environment = {k: v for k, v in os.environ.items() if not k.startswith(("APPLE_", "DEVELOPER_ID", "SIGN_"))}
        # A service that does not exist, so tests never read the developer's own Keychain items.
        environment["KEYCHAIN_SERVICE"] = "macsign-tests"
        patch = mock.patch.dict(os.environ, environment, clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    def write(self, path: str, content: bytes = b"") -> Path:
        target = self.dir / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def binary(self, path: str) -> Path:
        target = self.write(path)
        shutil.copy("/usr/bin/true", target)
        return target

    def bundle(self, path: str) -> Path:
        """A bundle with an Info.plist and a main executable."""
        name = Path(path).stem
        info = {"CFBundleExecutable": name, "CFBundleIdentifier": f"t.{name}", "CFBundleShortVersionString": "1.2"}
        self.write(f"{path}/Contents/Info.plist", plistlib.dumps(info))
        self.binary(f"{path}/Contents/MacOS/{name}")
        return self.dir / path

    def app_with_nested_code(self) -> Path:
        app = self.bundle("My App.app")
        framework = "My App.app/Contents/Frameworks/Kit.framework"
        self.binary(f"{framework}/Versions/A/Kit")
        self.binary(f"{framework}/Versions/A/Helpers/tool")
        info = {"CFBundleExecutable": "Kit", "CFBundleIdentifier": "t.Kit"}
        self.write(f"{framework}/Versions/A/Resources/Info.plist", plistlib.dumps(info))
        for link, target in (
            ("Versions/Current", "A"),
            ("Kit", "Versions/Current/Kit"),
            ("Resources", "Versions/Current/Resources"),
        ):
            (self.dir / framework / link).symlink_to(target)
        self.bundle("My App.app/Contents/XPCServices/Service.xpc")
        self.binary("My App.app/Contents/Frameworks/libthing.dylib")
        self.write("My App.app/Contents/Resources/Strings.bundle/Contents/Info.plist", plistlib.dumps({"a": "b"}))
        self.write("My App.app/Contents/Resources/run.sh", b"#!/bin/sh\n")
        return app


class IdentityTests(unittest.TestCase):
    def test_parse_drops_duplicates_and_the_summary_line(self) -> None:
        output = find_identity_output(RELEASE, DEVELOPMENT, RELEASE)
        self.assertEqual(macsign.parse_identities(output), [RELEASE, DEVELOPMENT])

    def test_parse_nothing_installed(self) -> None:
        self.assertEqual(macsign.parse_identities(find_identity_output()), [])

    def test_choose_the_only_one_of_its_kind(self) -> None:
        chosen = macsign.choose_identity([DEVELOPMENT, RELEASE], None, macsign.DEVELOPER_ID)
        self.assertEqual(chosen, RELEASE)

    def test_choose_fails_when_ambiguous_and_lists_the_hashes(self) -> None:
        with self.assertRaisesRegex(Failure, f"(?s){RELEASE.sha1}.*{RENEWED.sha1}"):
            macsign.choose_identity([RELEASE, RENEWED], RELEASE.name, macsign.DEVELOPER_ID)

    def test_choose_by_hash_or_part_of_name(self) -> None:
        self.assertEqual(macsign.choose_identity([RELEASE, RENEWED], RENEWED.sha1.lower()), RENEWED)
        self.assertEqual(macsign.choose_identity([RELEASE, DEVELOPMENT], "TEAMID1234"), RELEASE)

    def test_an_exact_name_beats_a_longer_one(self) -> None:
        longer = Identity("D" * 40, RELEASE.name + " Extra")
        self.assertEqual(macsign.choose_identity([longer, RELEASE], RELEASE.name), RELEASE)

    @mock.patch.dict(os.environ, clear=True)
    def test_release_refuses_other_kinds_and_ad_hoc(self) -> None:
        sh = FakeShell(("find-identity", 0, find_identity_output(DEVELOPMENT), ""))
        for wanted in (None, DEVELOPMENT.name, "-"):
            with self.subTest(wanted), self.assertRaises(Failure):
                macsign.release_identity(sh, wanted)

    @mock.patch.dict(os.environ, clear=True)
    def test_development_falls_back_to_ad_hoc_only_when_none_was_asked_for(self) -> None:
        sh = FakeShell(("find-identity", 0, find_identity_output(RELEASE), ""))
        self.assertEqual(macsign.development_identity(sh, None), AD_HOC)
        with self.assertRaises(Failure):
            macsign.development_identity(sh, "Nobody")

    def test_environment_selects_the_release_identity(self) -> None:
        sh = FakeShell(("find-identity", 0, find_identity_output(RELEASE, RENEWED), ""))
        with mock.patch.dict(os.environ, {"DEVELOPER_ID_APPLICATION": RENEWED.sha1}):
            self.assertEqual(macsign.release_identity(sh, None), RENEWED)

    def test_team_id_is_read_from_the_matching_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            pems = {}
            for team in ("OTHERTEAM1", "TEAMID1234"):
                pems[team] = subprocess.run(
                    [
                        *("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{folder}/key"),
                        *("-subj", f"/UID=x/CN=Jane/OU={team}/O=Jane"),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
        listing = (
            f"SHA-256 hash: {'0' * 64}\nSHA-1 hash: {RELEASE.sha1}\n{pems['OTHERTEAM1']}"
            f"SHA-256 hash: {'1' * 64}\nSHA-1 hash: {DEVELOPMENT.sha1}\n{pems['TEAMID1234']}"
        )

        class CertificateShell(FakeShell):
            def read(self, *cmd: macsign.Arg, stdin: str = "") -> subprocess.CompletedProcess[str]:
                return Shell.read(self, *cmd, stdin=stdin) if cmd[0] == "openssl" else super().read(*cmd)

        sh = CertificateShell(("find-certificate", 0, listing, ""))
        self.assertEqual(macsign.team_id(sh, DEVELOPMENT), "TEAMID1234")
        with self.assertRaises(Failure):
            macsign.team_id(sh, RENEWED)


class BundleTests(TempDirCase):
    def test_macho_detection(self) -> None:
        self.assertTrue(macsign.is_macho(self.binary("binary")))
        for name, content in (
            ("java", b"\xca\xfe\xba\xbe\x00\x00\x00\x41"),
            ("script", b"#!/bin/sh"),
            ("empty", b""),
            ("truncated", b"\xca\xfe\xba\xbe"),
        ):
            with self.subTest(name):
                self.assertFalse(macsign.is_macho(self.write(name, content)))

    def test_nested_code_is_deepest_first_without_main_executables_or_data(self) -> None:
        self.assertEqual(
            [str(path) for path in macsign.nested_code(self.app_with_nested_code())],
            [
                "Contents/Frameworks/Kit.framework/Versions/A/Helpers/tool",
                "Contents/Frameworks/Kit.framework",
                "Contents/Frameworks/libthing.dylib",
                "Contents/XPCServices/Service.xpc",
            ],
        )

    def test_unreadable_nested_plist_does_not_stop_signing(self) -> None:
        app = self.bundle("A.app")
        self.write("A.app/Contents/Resources/Odd.bundle/Contents/Info.plist", b"not a plist")
        self.assertEqual(macsign.nested_code(app), [])

    def test_not_an_app(self) -> None:
        with self.assertRaises(Failure):
            macsign.open_app(self.dir)

    def test_staging_refuses_to_overlap_the_original(self) -> None:
        app = self.bundle("A.app")
        inner = self.bundle("A.app/Contents/Resources/A.app")
        for original, folder in ((app, self.dir), (inner, self.dir), (app, app / "Contents")):
            sh = FakeShell()
            with self.subTest(f"{original} {folder}"), self.assertRaisesRegex(Failure, "overlap"):
                macsign.stage(sh, App(original, original), folder)
            self.assertEqual(sh.commands, [])

    def test_staging_refuses_the_original_by_another_name(self) -> None:
        app = self.bundle("build/A.app")
        link = self.dir / "link"
        link.symlink_to(app.parent)
        aliases = [link]
        if (self.dir / "BUILD").exists():  # false on a case-sensitive volume
            aliases.append(self.dir / "BUILD")
        for folder in aliases:
            with self.subTest(folder), self.assertRaisesRegex(Failure, "overlap"):
                macsign.stage(Shell(), App(app, app), folder)
            self.assertTrue(app.exists())

    def test_install_refuses_to_replace_its_input(self) -> None:
        app = self.bundle("apps/A.app")
        before = sorted((path, path.read_bytes()) for path in macsign.files_in(app))
        for folder, stage in (("apps", "s"), ("s", "s")):
            argv = [str(app), "--identity", "-", "--dir", str(self.dir / folder), "--stage", str(self.dir / stage)]
            (self.dir / stage / "A.app").mkdir(parents=True, exist_ok=True)
            self.assertEqual(macsign.main(["install", *argv]), 1)
            self.assertIn("overlap", self.output.getvalue())
        self.assertEqual(sorted((path, path.read_bytes()) for path in macsign.files_in(app)), before)

    def test_otool_reads_names_with_brackets(self) -> None:
        path = self.binary("Helper (GPU)")
        result = macsign.linked_libraries(Shell(), path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("libSystem", result.stdout)

    def test_options_refuse_directories_and_empty_paths(self) -> None:
        app = self.bundle("A.app")
        for option in ("--entitlements", "--profile", "--stage"):
            for value in ("", str(self.dir)) if option != "--stage" else ("",):
                with self.subTest(f"{option} {value}"), self.assertRaises(SystemExit):
                    macsign.main(["sign", str(app), option, value])

    def test_entitlements_get_the_team_id_from_xml_or_binary(self) -> None:
        data = {"groups": ["__TEAM_ID__.group"], "com.apple.security.device.audio-input": True}
        for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            path = self.write("e.entitlements", plistlib.dumps(data, fmt=fmt))
            rendered = plistlib.loads(macsign.render_entitlements(path, "TEAMID1234"))
            self.assertEqual(rendered, {**data, "groups": ["TEAMID1234.group"]})

    def test_dmg_name_needs_a_version(self) -> None:
        app = self.bundle("A.app")
        self.assertEqual(macsign.dmg_path(App(app, app), Path("dist")), Path("dist/A-1.2.dmg"))
        self.write("A.app/Contents/Info.plist", plistlib.dumps({"CFBundleExecutable": "A"}))
        with self.assertRaises(Failure):
            macsign.dmg_path(App(app, app), Path("dist"))


class SigningTests(TempDirCase):
    def test_release_flags(self) -> None:
        app = self.bundle("A.app")
        sh = FakeShell()
        macsign.sign(sh, App(app, app), RELEASE, True, None, None)
        self.assertEqual(
            sh.commands[0],
            f"codesign --force --sign {RELEASE.sha1} --timestamp --options runtime "
            f"--preserve-metadata=entitlements {app}",
        )

    def test_ad_hoc_has_no_hardened_runtime_or_timestamp(self) -> None:
        app = self.bundle("A.app")
        sh = FakeShell()
        macsign.sign(sh, App(app, app), AD_HOC, False, None, None)
        self.assertIn("--timestamp=none", sh.commands[0])
        self.assertNotIn("runtime", sh.commands[0])

    def test_release_command_uses_everything_it_is_given(self) -> None:
        app = self.bundle("A.app")
        shutil.copytree(app, self.dir / "s/A.app")  # FakeShell does not copy
        profile = self.write("p.provisionprofile")
        wanted = self.write("e.entitlements", plistlib.dumps({"groups": ["__TEAM_ID__.g"]}))
        rendered: list[Any] = []

        class SigningShell(FakeShell):
            def read(self, *cmd: macsign.Arg, stdin: str = "") -> subprocess.CompletedProcess[str]:
                if "--entitlements" in cmd:
                    rendered.append(plistlib.loads(Path(cmd[cmd.index("--entitlements") + 1]).read_bytes()))
                return super().read(*cmd, stdin=stdin)

        sh = SigningShell(("find-identity", 0, find_identity_output(RELEASE, DEVELOPMENT), ""))
        argv = ["sign", str(app), "--release", "--stage", str(self.dir / "s"), "--profile", str(profile)]
        with (
            mock.patch.object(macsign, "Shell", return_value=sh),
            mock.patch.object(macsign, "team_id", return_value="TEAMID1234"),
        ):
            self.assertEqual(macsign.main([*argv, "--entitlements", str(wanted)]), 0, self.output.getvalue())
        self.assertEqual(rendered, [{"groups": ["TEAMID1234.g"]}])
        steps = ["xattr -cr", f"cp {profile}", f"codesign --force --sign {RELEASE.sha1} --timestamp --options runtime"]
        positions = [next(n for n, c in enumerate(sh.commands) if step in c) for step in steps]
        self.assertEqual(positions, sorted(positions))

    def test_failed_codesign_shows_its_output(self) -> None:
        app = self.bundle("A.app")
        sh = FakeShell(("codesign", 1, "", "errSecInternalComponent"))
        with self.assertRaisesRegex(Failure, "errSecInternalComponent"):
            macsign.sign(sh, App(app, app), RELEASE, True, None, None)

    def test_real_ad_hoc_sign_and_verify(self) -> None:
        app = self.app_with_nested_code()
        service = app / "Contents/XPCServices/Service.xpc"
        jit = self.write("jit.entitlements", plistlib.dumps({"com.apple.security.cs.allow-jit": True}))
        subprocess.run(
            ["codesign", "--force", "--sign", "-", "--entitlements", str(jit), str(service)],
            check=True,
            capture_output=True,
        )
        before = sorted((path, path.read_bytes()) for path in macsign.files_in(app))
        wanted = self.write("a.entitlements", plistlib.dumps({"com.apple.security.device.camera": True}))
        stage = self.dir / "stage"

        arguments = [str(app), "--identity", "-", "--entitlements", str(wanted), "--stage", str(stage)]
        self.assertEqual(macsign.main(["sign", *arguments]), 0, self.output.getvalue())

        signed = stage / app.name
        sh = Shell()
        self.assertEqual(macsign.main(["verify", str(signed), "--entitlements", str(wanted)]), 0)
        self.assertEqual(macsign.entitlements_of(sh, signed), {"com.apple.security.device.camera": True})
        nested = macsign.entitlements_of(sh, signed / service.relative_to(app))
        self.assertEqual(nested, {"com.apple.security.cs.allow-jit": True})
        self.assertEqual(sorted((path, path.read_bytes()) for path in macsign.files_in(app)), before)

        self.assertEqual(macsign.main(["verify", str(signed), "--entitlements", str(jit)]), 1)
        self.assertIn(
            "entitlement missing from the signed app: com.apple.security.cs.allow-jit", self.output.getvalue()
        )
        with (signed / "Contents/Resources/run.sh").open("a") as f:
            f.write("tampered")
        self.assertEqual(macsign.main(["verify", str(signed)]), 1)

    def test_install_replaces_the_old_copy(self) -> None:
        app = self.bundle("A.app")
        stale = self.write("Applications/A.app/stale")
        arguments = [
            str(app),
            "--identity",
            "-",
            "--stage",
            str(self.dir / "s"),
            "--dir",
            str(self.dir / "Applications"),
        ]
        self.assertEqual(macsign.main(["install", *arguments]), 0, self.output.getvalue())
        self.assertIn(f"codesign --verify --deep --strict {self.dir}/Applications/A.app", self.output.getvalue())
        self.assertFalse(stale.exists())
        self.assertEqual(os.listdir(self.dir / "Applications"), ["A.app"])


class NotariseTests(TempDirCase):
    AUTH = ("--keychain-profile", "p")

    def notarise(self, status: str, staple_codes: tuple[int, ...] = (0,)) -> FakeShell:
        codes = iter(staple_codes)

        class NotaryShell(FakeShell):
            def run_live(self, *cmd: macsign.Arg, interactive: bool = False) -> bool:
                succeeded = super().run_live(*cmd)
                return next(codes) == 0 if "staple" in cmd else succeeded

        self.sh = NotaryShell(
            ("notarytool submit", 0, '{"id": "ID-1"}', ""),
            ("notarytool wait", 0, json.dumps({"status": status}), ""),
        )
        with mock.patch("time.sleep") as self.sleep:
            macsign.notarise(self.sh, list(self.AUTH), Path("a.zip"), Path("A.app"))
        return self.sh

    def test_accepted_is_stapled(self) -> None:
        sh = self.notarise("Accepted")
        self.assertEqual(
            sh.commands,
            [
                "xcrun notarytool submit a.zip --keychain-profile p --no-wait --output-format json",
                "xcrun notarytool wait ID-1 --keychain-profile p --timeout 2h --output-format json",
                "xcrun stapler staple A.app",
            ],
        )

    def test_staple_is_retried(self) -> None:
        self.notarise("Accepted", (1, 1, 0))
        self.assertEqual(self.sleep.call_count, 2)
        with self.assertRaisesRegex(Failure, "stapling"):
            self.notarise("Accepted", (1, 1, 1))

    def test_invalid_shows_the_log_and_does_not_staple(self) -> None:
        for status in ("Invalid", "Rejected"):
            with self.subTest(status), self.assertRaisesRegex(Failure, "rejected"):
                self.notarise(status)
            self.assertEqual(self.sh.commands[-1], "xcrun notarytool log ID-1 --keychain-profile p")

    def test_timeout_names_the_submission(self) -> None:
        with self.assertRaisesRegex(Failure, "ID-1"):
            self.notarise("In Progress")
        self.assertNotIn("staple", " ".join(self.sh.commands))

    def test_failed_upload(self) -> None:
        sh = FakeShell(("submit", 0, '{"message": "no agreement"}', ""))
        with self.assertRaisesRegex(Failure, "no agreement"):
            macsign.notarise(sh, list(self.AUTH), Path("a.zip"), Path("A.app"))

    def test_json_survives_other_output(self) -> None:
        sh = Shell()
        self.assertEqual(sh.run_json("echo", '{"id": "x"}'), {"id": "x"})
        self.assertEqual(sh.run_json("echo", "Error: 401"), {})
        self.assertEqual(sh.run_json("false"), {})

    def auth(self, *argv: str, sh: FakeShell | None = None) -> list[str]:
        with macsign.notary_auth(sh or FakeShell(), macsign.build_parser().parse_args(["history", *argv])) as auth:
            return auth

    def stored_key(self, content: bytes = b"-----BEGIN PRIVATE KEY-----\nx", dry_run: bool = False) -> FakeShell:
        return FakeShell(
            ("-a api-key -w", 0, "STOREDKEY1\n", ""),
            ("-a api-issuer -w", 0, "stored-issuer\n", ""),
            ("-a api-key-file -w", 0, base64.b64encode(content).decode() + "\n", ""),
            ("-a api-key", 0, "", ""),
            dry_run=dry_run,
        )

    def test_stored_key_is_used_without_setup_and_removed_afterwards(self) -> None:
        args = macsign.build_parser().parse_args(["history"])
        with macsign.notary_auth(self.stored_key(), args) as auth:
            path = Path(auth[3])
            self.assertEqual(auth, ["--key-id", "STOREDKEY1", "--key", str(path), "--issuer", "stored-issuer"])
            self.assertEqual(path.read_bytes(), b"-----BEGIN PRIVATE KEY-----\nx")
            self.assertEqual(path.parent.stat().st_mode & 0o077, 0)
        self.assertFalse(path.exists())

    def test_stored_key_must_be_a_key(self) -> None:
        with self.assertRaisesRegex(Failure, "api-key-file"):
            self.auth(sh=self.stored_key(b"something else"))

    def test_dry_run_never_reads_the_stored_key(self) -> None:
        sh = self.stored_key(dry_run=True)
        self.assertEqual(self.auth(sh=sh)[:2], ["--key-id", "STOREDKEY1"])
        self.assertNotIn("api-key-file -w", " ".join(sh.commands))

    def test_options_beat_the_stored_key(self) -> None:
        self.assertEqual(self.auth("--keychain-profile", "p", sh=self.stored_key()), ["--keychain-profile", "p"])
        self.assertEqual(self.auth("--key", "k", "--key-id", "K", sh=self.stored_key())[1], "K")

    def test_auth_precedence(self) -> None:
        self.assertEqual(self.auth(), ["--keychain-profile", "apple-release"])
        key = ["--key-id", "K", "--key", "k.p8"]
        self.assertEqual(self.auth(*key), key)
        self.assertEqual(self.auth(*key, "--issuer", "I"), [*key, "--issuer", "I"])
        self.assertEqual(self.auth(*key, "--keychain-profile", "p"), ["--keychain-profile", "p"])
        with self.assertRaises(Failure):
            self.auth("--issuer", "I")

    def test_auth_from_the_environment(self) -> None:
        variables = {"APPLE_API_KEY_PATH": "k.p8", "APPLE_API_KEY": "K", "APPLE_API_ISSUER": "I"}
        with mock.patch.dict(os.environ, variables):
            self.assertEqual(self.auth(), ["--key-id", "K", "--key", "k.p8", "--issuer", "I"])

    def test_empty_environment_counts_as_unset(self) -> None:
        with mock.patch.dict(os.environ, {"APPLE_API_KEY_PATH": "", "APPLE_API_KEY": "", "APPLE_API_ISSUER": ""}):
            self.assertEqual(self.auth(), ["--keychain-profile", "apple-release"])


class CheckTests(TempDirCase):
    def test_gatekeeper_and_staples_are_checked(self) -> None:
        app = self.bundle("A.app")
        dmg = self.write("A.dmg")
        good = "flags=0x10000(runtime)\nAuthority=Developer ID Application: J\nTimestamp=now\nTeamIdentifier=T\n"
        for rejected in ("spctl --assess --type execute", "spctl --assess --type open", f"validate {app}", "validate"):
            sh = FakeShell((rejected, 1, "", "rejected"), ("-dvv", 0, "", "Executable=/A\n" + good))
            with self.subTest(rejected), self.assertRaises(Failure):
                macsign.verify(sh, App(app, app), dmg, None)

    def test_ready(self) -> None:
        sh = FakeShell(("find-identity", 0, find_identity_output(RELEASE), ""))
        macsign.check(sh, None, ["--keychain-profile", "p"])
        self.assertNotIn("FAIL", self.output.getvalue())

    def test_every_problem_is_reported(self) -> None:
        sh = FakeShell(("--find stapler", 1, "", ""), ("history", 1, "", "HTTP status code: 401"))
        with self.assertRaises(Failure):
            macsign.check(sh, None, ["--keychain-profile", "p"])
        for problem in ("stapler not found", "no Developer ID Application certificate", "401"):
            self.assertIn(problem, self.output.getvalue())

    def test_parse_signature(self) -> None:
        output = (
            "Executable=/A\nCodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1\n"
            "Authority=Developer ID Application: Jane (TEAMID1234)\nTimestamp=1 Jan 2026\nTeamIdentifier=TEAMID1234\n"
        )
        self.assertEqual(macsign.parse_signature(output), macsign.Signature("TEAMID1234", True, True, True))
        ad_hoc = "Executable=/A\nCodeDirectory flags=0x2(adhoc) hashes=1\nSignature=adhoc\nTeamIdentifier=not set\n"
        self.assertEqual(macsign.parse_signature(ad_hoc), macsign.Signature("not set", False, False, False))

    def test_local_libraries(self) -> None:
        output = (
            "/usr/local/My App.app/x:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
            "\t/opt/homebrew/lib/liba.dylib (compatibility version 1.0.0)\n\t@rpath/libb.dylib (compat)\n"
        )
        self.assertEqual(macsign.local_libraries(output), ["/opt/homebrew/lib/liba.dylib"])

    def test_release_problems_in_nested_code(self) -> None:
        app = self.app_with_nested_code()
        good = (
            "CodeDirectory flags=0x10000(runtime)\nAuthority=Developer ID Application: J (T)\n"
            "Timestamp=now\nTeamIdentifier=TEAMID1234\n"
        )
        bad = "CodeDirectory flags=0x0(none)\nAuthority=Apple Development: J\nTeamIdentifier=OTHERTEAM1\n"
        debug = plistlib.dumps({"com.apple.security.get-task-allow": True}).decode()
        sh = FakeShell(
            (f"-dvv {app}/Contents/Frameworks/libthing.dylib", 0, "", bad),
            ("-dvv", 0, "", good),
            (f"--xml {app}/Contents/XPCServices", 0, debug, ""),
        )
        with self.assertRaises(Failure):
            macsign.verify(sh, App(app, app), None, None)
        failures = [line for line in self.output.getvalue().splitlines() if "FAIL" in line]
        self.assertEqual(len(failures), 4, failures)
        for problem in ("no hardened runtime", "no secure timestamp", "signed by another team", "get-task-allow"):
            self.assertIn(problem, self.output.getvalue())


class CommandTests(TempDirCase):
    def test_release_order(self) -> None:
        app = self.bundle("A.app")
        sh = FakeShell(
            ("find-identity", 0, find_identity_output(RELEASE), ""),
            ("notarytool submit", 0, '{"id": "ID-1"}', ""),
            ("notarytool wait", 0, '{"status": "Accepted"}', ""),
        )
        stage, dist = self.dir / "stage", self.dir / "dist"
        # FakeShell runs nothing, so what the commands would have made is put in place.
        shutil.copytree(app, stage / "A.app")
        dmg = self.write("dist/A-1.2.dmg")
        argv = ["release", str(app), "--stage", str(stage), "--out", str(dist)]
        with mock.patch.object(macsign, "Shell", return_value=sh):
            self.assertEqual(macsign.main(argv), 0, self.output.getvalue())
        steps = ["notarytool history", f"ditto {app} {stage}/A.app", "codesign --force", "notarytool submit"]
        steps += ["stapler staple", "hdiutil create", "hdiutil attach", "hdiutil detach", "hdiutil convert"]
        steps += [f"--timestamp {dmg}", f"notarytool submit {dmg}", f"stapler staple {dmg}", "stapler validate"]
        position = 0
        for step in steps:
            found = [n for n, command in enumerate(sh.commands) if step in command and n >= position]
            self.assertTrue(found, f"{step} missing or out of order in {sh.commands}")
            position = found[0]

    def test_release_stops_before_changing_anything_when_not_ready(self) -> None:
        app = self.bundle("A.app")
        sh = FakeShell(("find-identity", 0, find_identity_output(RELEASE), ""), ("history", 1, "", "401"))
        with mock.patch.object(macsign, "Shell", return_value=sh):
            self.assertEqual(macsign.main(["release", str(app), "--stage", str(self.dir / "s")]), 1)
        self.assertFalse([c for c in sh.commands if c.startswith(("ditto", "rm", "codesign"))])

    def test_dry_run_prints_everything_and_changes_nothing(self) -> None:
        app = self.app_with_nested_code()
        before = sorted(self.dir.rglob("*"))
        argv = ["release", str(app), "--dry-run", "--stage", str(self.dir / "s"), "--out", str(self.dir / "d")]
        with mock.patch.object(macsign, "installed_identities", return_value=[]):
            self.assertEqual(macsign.main(argv), 0, self.output.getvalue())
        self.assertEqual(sorted(self.dir.rglob("*")), before)
        printed = self.output.getvalue()
        for text in (
            f"{self.dir}/s/My App.app/Contents/XPCServices",
            "notarytool submit",
            "hdiutil convert",
            "stapler",
        ):
            self.assertIn(text, printed)

    def test_dmg_is_detached_when_copying_fails(self) -> None:
        app = self.bundle("A.app")
        sh = FakeShell(("ditto", 1, "", "disk full"))
        with self.assertRaisesRegex(Failure, "disk full"):
            macsign.create_dmg(sh, App(app, app), self.dir / "A.dmg", RELEASE)
        self.assertIn("detach", sh.commands[-1])

    def test_setup_passes_on_only_what_was_given(self) -> None:
        sh = FakeShell()
        args = argparse.Namespace(key=None, key_id="K", issuer=None, keychain_profile=None, identity=None)
        macsign.cmd_setup(sh, args)
        self.assertEqual(sh.commands[-1], "xcrun notarytool store-credentials apple-release --key-id K")

    def test_setup_has_nothing_to_do_with_a_stored_key(self) -> None:
        sh = FakeShell(("find-generic-password", 0, "", ""))
        macsign.cmd_setup(sh, macsign.build_parser().parse_args(["setup"]))
        self.assertNotIn("store-credentials", " ".join(sh.commands))

    def test_setup_saves_an_identity_that_is_then_used(self) -> None:
        sh = FakeShell(("find-identity", 0, find_identity_output(RELEASE, RENEWED, DEVELOPMENT), ""))
        macsign.cmd_setup(sh, macsign.build_parser().parse_args(["setup", "--identity", RENEWED.sha1]))
        saved = f"-a signing-identity -w {RENEWED.sha1}"
        self.assertIn(saved, sh.commands[-1])
        sh = FakeShell(
            ("find-identity", 0, find_identity_output(RELEASE, RENEWED), ""),
            ("-a signing-identity -w", 0, RENEWED.sha1 + "\n", ""),
        )
        self.assertEqual(macsign.release_identity(sh, None), RENEWED)

    def test_commands_cannot_wait_for_input(self) -> None:
        with mock.patch("subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = b"{}"
            Shell().run_live("true")
            Shell().run_json("true")
            Shell().read("true")
            for call in run.call_args_list:
                closed = call.kwargs.get("stdin") == subprocess.DEVNULL or call.kwargs.get("input") == ""
                self.assertTrue(closed, call)

    def test_errors_have_no_traceback(self) -> None:
        self.assertEqual(macsign.main(["verify", str(self.dir)]), 1)
        self.assertIn("ERROR:", self.output.getvalue())


if __name__ == "__main__":
    unittest.main()
