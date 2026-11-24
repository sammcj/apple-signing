#!/usr/bin/env python3
"""Sign, notarise, staple and package a macOS app for distribution outside the App Store.

Standard library only, for the Python 3.9 that comes with Xcode, so this file can be copied into a project and run.
Commands that change something are printed before they run. --dry-run prints them without running them.
Only setup asks for anything. Every other command runs with no standard input, so it fails rather than waits.
"""

from __future__ import annotations

import argparse
import base64
import functools
import json
import os
import plistlib
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union

__version__ = "0.1.0"

DEFAULT_KEYCHAIN_PROFILE = "apple-release"
DEVELOPER_ID = "Developer ID Application: "
APPLE_DEVELOPMENT = "Apple Development: "
NESTED_BUNDLES = {".framework", ".app", ".xpc", ".appex", ".bundle", ".plugin", ".systemextension"}
THIN_MAGIC = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
FAT_MAGIC = {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}
TEAM_PLACEHOLDER = "__TEAM_ID__"
STAPLE_ATTEMPTS = 3
STAPLE_RETRY_SECONDS = 15

Arg = Union[str, Path]

# Unbuffered, so this output and that of the commands stay in order in a CI log.
say = functools.partial(print, flush=True)


class Failure(Exception):
    """An error to show the user without a traceback."""


class Shell:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def announce(self, cmd: tuple[Arg, ...]) -> None:
        # Not secret, but they identify the account and CI logs can be public.
        hidden = ("--key-id", "--issuer")
        words = ["***" if n and cmd[n - 1] in hidden else str(word) for n, word in enumerate(cmd)]
        print(f"+ {' '.join(w if w == '***' else shlex.quote(w) for w in words)}", file=sys.stderr, flush=True)

    def report(self, message: str) -> None:
        """Say that something happened, which in a dry run it did not."""
        if not self.dry_run:
            say(message)

    def run(self, *cmd: Arg) -> str:
        """Run a command that changes something. Returns its output, raises Failure if it fails."""
        self.announce(cmd)
        if self.dry_run:
            return ""
        result = self.read(*cmd)
        output = result.stdout + result.stderr
        if result.returncode:
            raise Failure(f"{cmd[0]} exited with {result.returncode}\n{output.strip()}")
        return output

    def run_live(self, *cmd: Arg, interactive: bool = False) -> bool:
        """Run a command that writes to the terminal. Returns whether it succeeded."""
        self.announce(cmd)
        if self.dry_run:
            return True
        stdin = None if interactive else subprocess.DEVNULL
        return subprocess.run([str(c) for c in cmd], check=False, stdin=stdin).returncode == 0

    def run_json(self, *cmd: Arg) -> dict[str, Any]:
        """Run a command that prints a JSON object. Returns {} when it prints anything else."""
        self.announce(cmd)
        if self.dry_run:
            return {}
        # stderr is left attached, so upload errors are seen as they happen.
        output = subprocess.run(
            [str(c) for c in cmd], check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE
        ).stdout
        try:
            parsed = json.loads(output)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            return parsed
        print(output.decode(errors="replace").strip(), file=sys.stderr)
        return {}

    def read(self, *cmd: Arg, stdin: str = "") -> subprocess.CompletedProcess[str]:
        """Run a command that only reads, so it runs in a dry run too. The caller checks the exit code."""
        return subprocess.run(
            [str(c) for c in cmd],
            check=False,
            input=stdin,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )


# --- Keychain ---


def keychain_service() -> str:
    return os.environ.get("KEYCHAIN_SERVICE") or "apple-release"


def keychain_has(sh: Shell, account: str) -> bool:
    """Whether an item exists, without reading it."""
    return sh.read("security", "find-generic-password", "-s", keychain_service(), "-a", account).returncode == 0


def keychain_item(sh: Shell, account: str) -> str:
    result = sh.read("security", "find-generic-password", "-s", keychain_service(), "-a", account, "-w")
    return "" if result.returncode else result.stdout.strip()


# --- Identities ---


@dataclass(frozen=True)
class Identity:
    sha1: str  # what codesign is given, because names can be ambiguous
    name: str


AD_HOC = Identity("-", "ad-hoc")


def parse_identities(output: str) -> list[Identity]:
    """Parse 'security find-identity'. An identity in two keychains is listed twice, so duplicates are dropped."""
    found = re.findall(r'^\s*\d+\) ([0-9A-F]{40}) "(.*)"', output, re.MULTILINE)
    return list(dict.fromkeys(Identity(sha1, name) for sha1, name in found))


def choose_identity(identities: list[Identity], wanted: str | None, kind: str = "") -> Identity | None:
    """The one identity that starts with kind and matches wanted (SHA-1, name or part of a name)."""
    matches = [i for i in identities if i.name.startswith(kind)]
    if wanted:
        exact = [i for i in matches if wanted.upper() == i.sha1 or wanted == i.name]
        matches = exact or [i for i in matches if wanted in i.name]
    if len(matches) > 1:
        listing = "\n".join(f"  {i.sha1}  {i.name}" for i in matches)
        raise Failure(
            f"several identities match. Choose one with --identity, or save it with setup --identity:\n{listing}"
        )
    return matches[0] if matches else None


def installed_identities(sh: Shell) -> list[Identity]:
    return parse_identities(sh.read("security", "find-identity", "-v", "-p", "codesigning").stdout)


def release_identity(sh: Shell, wanted: str | None) -> Identity:
    wanted = wanted or os.environ.get("DEVELOPER_ID_APPLICATION") or keychain_item(sh, "signing-identity")
    if wanted == AD_HOC.sha1:
        raise Failure("a release cannot be signed ad-hoc")
    identity = choose_identity(installed_identities(sh), wanted, DEVELOPER_ID)
    if identity:
        return identity
    if sh.dry_run:
        return Identity(wanted or f"{DEVELOPER_ID}YOUR NAME (TEAMID1234)", "placeholder, no certificate installed")
    raise Failure(
        f"no Developer ID Application identity matching '{wanted}' with its private key in the Keychain"
        if wanted
        else "no Developer ID Application certificate with its private key in the Keychain"
    )


def development_identity(sh: Shell, wanted: str | None) -> Identity:
    wanted = wanted or os.environ.get("SIGN_IDENTITY") or keychain_item(sh, "dev-signing-identity")
    if wanted == AD_HOC.sha1:
        return AD_HOC
    identities = installed_identities(sh)
    if not wanted:
        try:
            return choose_identity(identities, None, APPLE_DEVELOPMENT) or AD_HOC
        except Failure as e:
            say(f"Falling back to ad-hoc signing: {e}")
            return AD_HOC
    identity = choose_identity(identities, wanted)
    if not identity:
        raise Failure(f"no identity matching '{wanted}' in the Keychain")
    return identity


def certificate_pem(output: str, sha1: str) -> str:
    """Pick one certificate out of 'security find-certificate -a -Z -p'."""
    for match in re.finditer(
        r"^SHA-1 hash: (\w+)$.*?(-----BEGIN.*?-----END CERTIFICATE-----)", output, re.MULTILINE | re.DOTALL
    ):
        if match[1] == sha1:
            return match[2]
    return ""


def team_id(sh: Shell, identity: Identity) -> str:
    """The Team ID is the OU of the certificate. The suffix of an Apple Development name is a per-person ID instead."""
    pem = certificate_pem(sh.read("security", "find-certificate", "-a", "-Z", "-p").stdout, identity.sha1)
    subject = sh.read("openssl", "x509", "-noout", "-subject", stdin=pem).stdout if pem else ""
    match = re.search(r"OU *= *([A-Z0-9]{10})\b", subject)
    if not match:
        raise Failure(f"no Team ID found in the certificate for '{identity.name}'")
    return match[1]


# --- Bundles ---


@dataclass(frozen=True)
class App:
    path: Path  # what commands act on
    source: Path  # what is inspected: path itself, except in a dry run, where nothing is copied to path


def open_app(path: Path) -> App:
    if path.suffix != ".app" or not (path / "Contents/Info.plist").is_file():
        raise Failure(f"{path} is not an app bundle")
    return App(path, path)


def read_plist(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as f:
            parsed = plistlib.load(f)
    except Exception as e:  # plistlib raises parser errors of several unrelated types
        raise Failure(f"cannot read {path}: {e}") from e
    if not isinstance(parsed, dict):
        raise Failure(f"{path} is not a dictionary plist")
    return parsed


def is_macho(path: Path) -> bool:
    with path.open("rb") as f:
        head = f.read(8)
    # Java classes share a magic number with universal binaries. There the next field is a version, 45 or more. Here it
    # is the number of architectures.
    return head[:4] in THIN_MAGIC or (
        head[:4] in FAT_MAGIC and len(head) == 8 and 0 < int.from_bytes(head[4:], "big") < 45
    )


def files_in(app: Path) -> list[Path]:
    return [
        path
        for root, _, names in os.walk(app / "Contents")
        for path in (Path(root, name) for name in names)
        if path.is_file() and not path.is_symlink()
    ]


def main_executable(bundle: Path) -> Path | None:
    """None when the bundle holds no code of its own."""
    if bundle.suffix == ".framework":
        folder, name = bundle, bundle.stem
        if (bundle / "Versions/Current").is_symlink():
            folder = bundle / "Versions" / os.readlink(bundle / "Versions/Current")
    else:
        plist = bundle / "Contents/Info.plist"
        if not plist.is_file():
            return None
        try:
            name = read_plist(plist).get("CFBundleExecutable", "")
        except Failure:
            return None
        folder = bundle / "Contents/MacOS"
    return folder / name if name and (folder / name).is_file() else None


def nested_code(app: Path) -> list[Path]:
    """Everything to sign before the app itself, deepest first, relative to the app."""
    main = main_executable(app)
    if not main:
        raise Failure(f"{app} has no main executable")
    bundles: list[Path] = []
    # A bundle's main executable is sealed by signing the bundle, so it is left out of the loose binaries.
    mains = {main}
    for root, folders, _ in os.walk(app / "Contents"):
        for path in (Path(root, name) for name in folders):
            if path.suffix not in NESTED_BUNDLES or path.is_symlink():
                continue
            main = main_executable(path)
            if main:
                mains.add(main)
                bundles.append(path)
    binaries = [
        path for path in files_in(app) if "_CodeSignature" not in path.parts and path not in mains and is_macho(path)
    ]
    relative = [path.relative_to(app) for path in bundles + binaries]
    return sorted(relative, key=lambda path: (-len(path.parts), str(path)))


def is_inside(path: Path, folder: Path) -> bool:
    """Whether path is folder or within it. Compares files rather than names, because most Macs ignore case in names."""
    if not folder.exists():
        return False
    resolved = path.resolve()
    return any(parent.exists() and parent.samefile(folder) for parent in (resolved, *resolved.parents))


def refuse_overlap(app: Path, target: Path) -> None:
    if is_inside(app, target) or is_inside(target, app):
        raise Failure(f"{app} and {target} overlap, so it would be overwritten. Choose another folder")


def stage(sh: Shell, app: App, folder: Path) -> App:
    """Copy the app, so the original is never changed."""
    target = folder / app.path.name
    refuse_overlap(app.path, target)
    sh.run("mkdir", "-p", folder)
    sh.run("rm", "-rf", target)
    sh.run("ditto", app.path, target)
    # codesign refuses Finder info and other extended attributes, which iCloud folders add. The full path, because pip
    # packages install an xattr without these options.
    sh.run("/usr/bin/xattr", "-cr", target)
    return App(target, app.source if sh.dry_run else target)


# --- Signing ---


def render_entitlements(path: Path, team: str) -> bytes:
    xml = plistlib.dumps(read_plist(path)).decode()
    return xml.replace(TEAM_PLACEHOLDER, team).encode()


def codesign(sh: Shell, *args: Arg) -> None:
    for line in sh.run("codesign", "--force", *args).splitlines():
        if line and not line.endswith(": replacing existing signature"):
            print(line, file=sys.stderr)


def sign(
    sh: Shell, app: App, identity: Identity, release: bool, entitlements: Path | None, profile: Path | None
) -> None:
    """Sign inside-out: nested code first, the app last.

    codesign --deep is not used to sign, because it would apply the app's entitlements to everything nested.
    """
    # Notarisation requires a secure timestamp. Development signing does without, so it works offline.
    flags = ["--sign", identity.sha1, "--timestamp" if release else "--timestamp=none"]
    if identity == AD_HOC:
        # Hardened runtime turns on library validation, which refuses ad-hoc frameworks because they have no Team ID.
        say("Signing ad-hoc, without hardened runtime")
    else:
        flags += ["--options", "runtime"]
        say(f"Signing with {identity.name}")

    # Nested code keeps its own entitlements: JIT helpers and Sparkle's Downloader need theirs.
    keep = "--preserve-metadata=entitlements"
    for item in nested_code(app.source):
        codesign(sh, *flags, keep, app.path / item)
    if profile:
        sh.run("cp", profile, app.path / "Contents/embedded.provisionprofile")
    if entitlements:
        team = "XXXXXXXXXX"
        placeholder = identity == AD_HOC or (sh.dry_run and not re.fullmatch(r"[0-9A-F]{40}", identity.sha1))
        if not placeholder and TEAM_PLACEHOLDER in str(read_plist(entitlements)):
            team = team_id(sh, identity)
        with tempfile.TemporaryDirectory() as work:
            rendered = Path(work, "app.entitlements")
            rendered.write_bytes(render_entitlements(entitlements, team))
            codesign(sh, *flags, "--entitlements", rendered, app.path)
    else:
        codesign(sh, *flags, keep, app.path)
    sh.run("codesign", "--verify", "--deep", "--strict", app.path)


# --- Notarising ---


def has_stored_api_key(sh: Shell) -> bool:
    return keychain_has(sh, "api-key") and keychain_has(sh, "api-key-file")


@contextmanager
def notary_auth(sh: Shell, args: argparse.Namespace) -> Generator[list[str], None, None]:
    """notarytool's credential options.

    In order: an explicit profile, an API key from the options, an API key in Keychain items (any part of which the
    options can replace), the default profile.
    """
    if args.keychain_profile:
        yield ["--keychain-profile", args.keychain_profile]
    elif args.key and args.key_id:
        yield api_key_options(args.key_id, args.key, args.issuer)
    elif has_stored_api_key(sh):
        # notarytool only reads an API key from a file. This one is in a directory only this user can read.
        with tempfile.TemporaryDirectory() as work:
            key = args.key or Path(work, "AuthKey.p8")
            if not args.key and not sh.dry_run:
                key.write_bytes(decode_api_key(keychain_item(sh, "api-key-file")))
            key_id = args.key_id or keychain_item(sh, "api-key")
            yield api_key_options(key_id, key, args.issuer or keychain_item(sh, "api-issuer"))
    elif args.key or args.key_id or args.issuer:
        raise Failure(
            "an API key needs --key and --key-id (APPLE_API_KEY_PATH and APPLE_API_KEY), plus --issuer for a Team "
            "key. To use stored credentials with those variables set, pass --keychain-profile"
        )
    else:
        yield ["--keychain-profile", DEFAULT_KEYCHAIN_PROFILE]


def api_key_options(key_id: str, key: Path, issuer: str | None) -> list[str]:
    # Individual keys have no issuer.
    return ["--key-id", key_id, "--key", str(key)] + (["--issuer", issuer] if issuer else [])


def decode_api_key(value: str) -> bytes:
    if not value:
        raise Failure(
            f"cannot read the Keychain item {keychain_service()}/api-key-file. If the keychain is locked, run: "
            "security unlock-keychain"
        )
    try:
        key = base64.b64decode(value, validate=True)
    except ValueError:
        key = b""
    if not key.startswith(b"-----BEGIN PRIVATE KEY-----"):
        raise Failure(f"the Keychain item {keychain_service()}/api-key-file does not hold a base64 .p8 key")
    return key


def notarise(sh: Shell, auth: list[str], submit: Path, staple: Path) -> None:
    """Submit a file to Apple's notary service, wait for the verdict and staple the ticket."""
    tool = ("xcrun", "notarytool")
    as_json = ("--output-format", "json")
    # Submitting and waiting are separate so the ID is on screen before a wait that can be long.
    result = sh.run_json(*tool, "submit", submit, *auth, "--no-wait", *as_json)
    submission = "SUBMISSION-ID" if sh.dry_run else result.get("id")
    if not submission:
        raise Failure(f"uploading {submit} failed: {result}")
    sh.report(f"Waiting for Apple, submission {submission}")
    result = sh.run_json(*tool, "wait", submission, *auth, "--timeout", "2h", *as_json)
    status = result.get("status")
    if status in ("Invalid", "Rejected"):
        sh.run_live(*tool, "log", submission, *auth)
        raise Failure(f"Apple rejected {submit}")
    if status != "Accepted" and not sh.dry_run:
        raise Failure(f"no verdict yet on submission {submission}. The history command shows its state. {result}")
    # The ticket can take a moment to be published.
    for attempt in range(STAPLE_ATTEMPTS):
        if attempt:
            time.sleep(STAPLE_RETRY_SECONDS)
        if sh.run_live("xcrun", "stapler", "staple", staple):
            return
    raise Failure(f"accepted, but stapling {staple} failed")


def notarise_app(sh: Shell, auth: list[str], app: App) -> None:
    # The notary service takes a zip, DMG or pkg, not a bare .app. The zip is only for the upload: a zip cannot be
    # stapled, so the app is.
    with tempfile.TemporaryDirectory() as work:
        archive = Path(work, f"{app.path.stem}.zip")
        sh.run("ditto", "-c", "-k", "--keepParent", app.path, archive)
        notarise(sh, auth, archive, app.path)


# --- DMG ---


def dmg_path(app: App, folder: Path) -> Path:
    version = read_plist(app.source / "Contents/Info.plist").get("CFBundleShortVersionString")
    if not version:
        raise Failure(f"{app.source} has no CFBundleShortVersionString")
    return folder / f"{app.path.stem}-{version}.dmg"


def image_megabytes(app: Path) -> int:
    """Room for the app, rounded up to whole blocks, plus a tenth and 20 MB for the filesystem."""
    size = sum(-(-path.stat().st_size // 4096) * 4096 for path in files_in(app))
    return size * 11 // 10 // 2**20 + 20


def create_dmg(sh: Shell, app: App, dmg: Path, identity: Identity) -> None:
    """Package an app into a signed DMG with an /Applications link.

    Creates, mounts, copies and converts explicitly. 'hdiutil create -srcfolder' can fail with "Operation not permitted"
    when macOS blocks its implicit mount under /Volumes.
    """
    with tempfile.TemporaryDirectory() as work:
        image, mount = Path(work, "rw.dmg"), Path(work, "mount")
        size = f"{image_megabytes(app.source)}m"
        sh.run("hdiutil", "create", "-volname", app.path.stem, "-fs", "HFS+", "-size", size, image)
        mount.mkdir()
        try:
            sh.run("hdiutil", "attach", image, "-mountpoint", mount, "-nobrowse", "-noverify", "-noautoopen")
            # ditto keeps signatures, extended attributes and the stapled ticket.
            sh.run("ditto", app.path, mount / app.path.name)
            sh.run("ln", "-s", "/Applications", mount / "Applications")
            sh.run("hdiutil", "detach", mount)
        except BaseException:
            # Left mounted, removing the temporary directory would fail and hide this error.
            sh.read("hdiutil", "detach", "-force", mount)
            raise
        sh.run("mkdir", "-p", dmg.parent)
        sh.run("rm", "-f", dmg)
        sh.run("hdiutil", "convert", image, "-format", "ULFO", "-o", dmg)
    codesign(sh, "--sign", identity.sha1, "--timestamp", dmg)


# --- Checks ---


class Report:
    def __init__(self) -> None:
        self.failed = False

    def ok(self, message: str) -> None:
        say(f"  ok    {message}")

    def fail(self, message: str) -> None:
        self.failed = True
        say(f"  FAIL  {message}")

    def command(self, label: str, result: subprocess.CompletedProcess[str]) -> None:
        if result.returncode:
            self.fail(f"{label}: {(result.stdout + result.stderr).strip()}")
        else:
            self.ok(label)

    def finish(self, message: str) -> None:
        if self.failed:
            raise Failure(message)


def check(sh: Shell, wanted: str | None, auth: list[str]) -> None:
    """Fail if a release would not work, before anything is built or uploaded."""
    report = Report()
    for tool in ("notarytool", "stapler"):
        if sh.read("xcrun", "--find", tool).returncode:
            report.fail(f"{tool} not found (install Xcode, then xcode-select)")
        else:
            report.ok(tool)
    try:
        report.ok(f"identity: {release_identity(sh, wanted).name}")
    except Failure as e:
        report.fail(str(e))
    # Catches a wrong ID, a revoked key and an unsigned agreement.
    label = f"Apple accepts the credentials ({auth[1] if auth[0] == '--keychain-profile' else 'API key'})"
    report.command(label, sh.read("xcrun", "notarytool", "history", *auth))
    report.finish("not ready to release. The setup command stores missing credentials")


@dataclass(frozen=True)
class Signature:
    team: str
    developer_id: bool
    hardened: bool
    timestamped: bool


def parse_signature(output: str) -> Signature:
    """Parse 'codesign -dvv'."""
    team = re.search(r"^TeamIdentifier=(.*)$", output, re.MULTILINE)
    return Signature(
        team=team[1] if team else "",
        developer_id="\nAuthority=Developer ID Application" in output,
        hardened=bool(re.search(r"flags=\S*runtime", output)),
        timestamped="\nTimestamp=" in output,
    )


def signature_of(sh: Shell, path: Path) -> Signature:
    return parse_signature(sh.read("codesign", "-dvv", path).stderr)


def entitlements_of(sh: Shell, path: Path) -> dict[str, Any]:
    xml = sh.read("codesign", "-d", "--entitlements", "-", "--xml", path).stdout
    return plistlib.loads(xml.encode()) if xml.strip() else {}


def linked_libraries(sh: Shell, path: Path) -> subprocess.CompletedProcess[str]:
    # Through a link, because otool takes the brackets in a name like "Helper (GPU)" to mean an archive member.
    with tempfile.TemporaryDirectory() as work:
        link = Path(work, "binary")
        link.symlink_to(path.resolve())
        return sh.read("otool", "-L", link)


def local_libraries(otool_output: str) -> list[str]:
    """Libraries in 'otool -L' output that only exist on a Mac with Homebrew."""
    return re.findall(r"^\t((?:/opt/homebrew|/usr/local)/\S+)", otool_output, re.MULTILINE)


def verify(sh: Shell, app: App, dmg: Path | None, entitlements: Path | None) -> None:
    """Report every problem found, then fail if there were any."""
    if dmg and not dmg.is_file():
        raise Failure(f"{dmg} not found")
    report = Report()
    report.command("app signature", sh.read("codesign", "--verify", "--deep", "--strict", app.path))

    # A missing entitlement does not fail at signing. macOS just denies the microphone, calendar and so on at run time.
    if entitlements:
        for key in sorted(read_plist(entitlements).keys() - entitlements_of(sh, app.path).keys()):
            report.fail(f"entitlement missing from the signed app: {key}")

    signature = signature_of(sh, app.path)
    for path in filter(is_macho, files_in(app.path)):
        libraries = linked_libraries(sh, path)
        if libraries.returncode:
            report.fail(f"otool cannot read {path}: {libraries.stderr.strip()}")
        for library in local_libraries(libraries.stdout):
            report.fail(f"links a library only this Mac has: {path} -> {library}")
        if not signature.developer_id:
            continue
        # Notarisation rejects the first three. A different team fails library validation at launch.
        nested = signature_of(sh, path)
        if not nested.hardened:
            report.fail(f"no hardened runtime: {path}")
        if not nested.timestamped:
            report.fail(f"no secure timestamp: {path}")
        if "com.apple.security.get-task-allow" in entitlements_of(sh, path):
            report.fail(f"debug entitlement get-task-allow: {path}")
        if nested.team != signature.team:
            report.fail(f"signed by another team: {path}")

    if signature.developer_id:
        report.command("app Gatekeeper", sh.read("spctl", "--assess", "--type", "execute", app.path))
        report.command("app staple", sh.read("xcrun", "stapler", "validate", app.path))
    else:
        say("  skip  release checks: the app is not Developer ID signed")
    if dmg:
        gatekeeper = ("spctl", "--assess", "--type", "open", "--context", "context:primary-signature")
        report.command("DMG signature", sh.read("codesign", "--verify", "--strict", dmg))
        report.command("DMG Gatekeeper", sh.read(*gatekeeper, dmg))
        report.command("DMG staple", sh.read("xcrun", "stapler", "validate", dmg))
    report.finish("verification failed")


# --- Commands ---


def cmd_setup(sh: Shell, args: argparse.Namespace) -> None:
    if args.identity:
        save_identity(sh, args.identity)
        return
    if not args.keychain_profile and has_stored_api_key(sh):
        service = keychain_service()
        items = ("api-key-file", "api-key", "api-issuer")
        replace = "\n".join(f"  security delete-generic-password -s {shlex.quote(service)} -a {i}" for i in items)
        message = (
            f"an API key is already stored in the Keychain items of '{service}'. To replace it, delete them:\n{replace}"
        )
        if args.key or args.key_id or args.issuer:
            raise Failure(message)
        say(f"Nothing to do, {message}")
        return
    given = {"--key": args.key, "--key-id": args.key_id, "--issuer": args.issuer}
    options = [word for option, value in given.items() if value for word in (option, value)]
    profile = args.keychain_profile or DEFAULT_KEYCHAIN_PROFILE
    if not sh.run_live("xcrun", "notarytool", "store-credentials", profile, *options, interactive=True):
        raise Failure("credentials not stored")


def save_identity(sh: Shell, wanted: str) -> None:
    identity = choose_identity(installed_identities(sh), wanted)
    if not identity:
        raise Failure(f"no identity matching '{wanted}' with its private key in the Keychain")
    accounts = {DEVELOPER_ID: "signing-identity", APPLE_DEVELOPMENT: "dev-signing-identity"}
    account = next((account for kind, account in accounts.items() if identity.name.startswith(kind)), None)
    if not account:
        raise Failure(f"'{identity.name}' is neither a Developer ID Application nor an Apple Development identity")
    # A hash is not secret, so it can be an argument.
    item = ("-s", keychain_service(), "-a", account, "-w", identity.sha1)
    sh.run("security", "add-generic-password", "-U", *item)
    sh.report(f"Saved {identity.name}")


def cmd_check(sh: Shell, args: argparse.Namespace) -> None:
    with notary_auth(sh, args) as auth:
        check(sh, args.identity, auth)


def stage_and_sign(sh: Shell, args: argparse.Namespace, release: bool) -> App:
    original = open_app(args.app)
    identity = (release_identity if release else development_identity)(sh, args.identity)
    app = stage(sh, original, args.stage)
    sign(sh, app, identity, release, args.entitlements, args.profile)
    sh.report(f"Signed {app.path}")
    return app


def cmd_sign(sh: Shell, args: argparse.Namespace) -> None:
    stage_and_sign(sh, args, args.release)


def cmd_install(sh: Shell, args: argparse.Namespace) -> None:
    installed = args.dir / args.app.name
    incoming = args.dir / f"{args.app.name}.new"
    for target in (installed, incoming):
        refuse_overlap(args.app, target)
        refuse_overlap(args.stage / args.app.name, target)
    # Not notarised: Gatekeeper only wants a ticket for downloaded (quarantined) apps.
    app = stage_and_sign(sh, args, release=False)
    sh.run("rm", "-rf", incoming)
    sh.run("ditto", app.path, incoming)
    sh.run("rm", "-rf", installed)
    sh.run("mv", incoming, installed)
    sh.run("codesign", "--verify", "--deep", "--strict", installed)
    sh.report(f"Installed {installed}")


def sign_and_notarise(sh: Shell, args: argparse.Namespace, auth: list[str]) -> App:
    open_app(args.app)
    if not sh.dry_run:
        check(sh, args.identity, auth)
    app = stage_and_sign(sh, args, release=True)
    notarise_app(sh, auth, app)
    return app


def package(sh: Shell, app: App, args: argparse.Namespace, auth: list[str]) -> Path:
    dmg = dmg_path(app, args.out)
    create_dmg(sh, app, dmg, release_identity(sh, args.identity))
    notarise(sh, auth, dmg, dmg)
    sh.report(f"Created {dmg}")
    return dmg


def cmd_notarise(sh: Shell, args: argparse.Namespace) -> None:
    with notary_auth(sh, args) as auth:
        sign_and_notarise(sh, args, auth)


def cmd_dmg(sh: Shell, args: argparse.Namespace) -> None:
    app = open_app(args.app)
    if not sh.dry_run and not signature_of(sh, app.path).developer_id:
        raise Failure(f"{app.path} is not Developer ID signed, so Apple would reject the DMG. Use release instead")
    with notary_auth(sh, args) as auth:
        package(sh, app, args, auth)


def cmd_release(sh: Shell, args: argparse.Namespace) -> None:
    dmg_path(open_app(args.app), args.out)  # fails now rather than after notarising
    with notary_auth(sh, args) as auth:
        # The app is stapled before it goes in the DMG, so it launches offline once copied out. The DMG gets its own
        # ticket.
        app = sign_and_notarise(sh, args, auth)
        dmg = package(sh, app, args, auth)
    if not sh.dry_run:
        verify(sh, app, dmg, args.entitlements)


def cmd_verify(sh: Shell, args: argparse.Namespace) -> None:
    verify(sh, open_app(args.app), args.dmg, args.entitlements)


def cmd_history(sh: Shell, args: argparse.Namespace) -> None:
    what = ["log", args.id] if args.id else ["history"]
    with notary_auth(sh, args) as auth:
        if not sh.run_live("xcrun", "notarytool", *what, *auth):
            raise Failure("notarytool failed")


def any_path(value: str) -> Path:
    if not value:
        raise argparse.ArgumentTypeError("empty path")
    # zsh passes --option=~/path through without expanding it.
    return Path(value).expanduser()


def existing_file(value: str) -> Path:
    path = any_path(value)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"{value} is not a file")
    return path


def build_parser() -> argparse.ArgumentParser:
    def options() -> argparse.ArgumentParser:
        return argparse.ArgumentParser(add_help=False, allow_abbrev=False)

    env = os.environ.get
    app = options()
    app.add_argument("app", type=any_path, help="a built .app")

    identity = options()
    identity.add_argument(
        "--identity", help="SHA-1, name or part of a name of the certificate. Only needed when several are installed"
    )

    entitlements = options()
    entitlements.add_argument(
        "--entitlements",
        type=existing_file,
        help=f"entitlements for the main app, where {TEAM_PLACEHOLDER} becomes your Team ID (default: keep its own)",
    )

    signing = options()
    signing.add_argument("--profile", type=existing_file, help="provisioning profile to embed")
    signing.add_argument(
        "--stage",
        type=any_path,
        default=Path("build/signing"),
        help="where the app is copied to (default: %(default)s)",
    )

    notary = options()
    notary.add_argument(
        "--keychain-profile",
        help=f"credentials stored with setup (default: a stored API key, else {DEFAULT_KEYCHAIN_PROFILE})",
    )
    notary.add_argument(
        "--key",
        type=any_path,
        default=env("APPLE_API_KEY_PATH") or None,
        help="API key .p8 file, or APPLE_API_KEY_PATH",
    )
    notary.add_argument("--key-id", default=env("APPLE_API_KEY"), help="API key ID, or APPLE_API_KEY")
    notary.add_argument("--issuer", default=env("APPLE_API_ISSUER"), help="API issuer ID, or APPLE_API_ISSUER")

    out = options()
    out.add_argument("--out", type=any_path, default=Path("dist"), help="where the DMG goes (default: %(default)s)")

    dry = options()
    dry.add_argument("--dry-run", action="store_true", help="print the commands without running them")

    parser = argparse.ArgumentParser(prog="macsign", description=(__doc__ or "").splitlines()[0], allow_abbrev=False)
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(metavar="command", required=True)

    def add(name: str, run: Any, text: str, *parents: argparse.ArgumentParser) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=text, description=text, parents=list(parents), allow_abbrev=False)
        sub.set_defaults(run=run)
        return sub

    add(
        "setup",
        cmd_setup,
        "store notarisation credentials in the Keychain, or --identity to save a choice",
        identity,
        notary,
        dry,
    )
    add("check", cmd_check, "fail if a release would not work", identity, notary)
    sub = add("sign", cmd_sign, "copy and sign an app", app, identity, entitlements, signing, dry)
    sub.add_argument("--release", action="store_true", help="sign with Developer ID rather than for development")
    sub = add("install", cmd_install, "development sign, then install", app, identity, entitlements, signing, dry)
    sub.add_argument(
        "--dir", type=any_path, default=Path("/Applications"), help="where to install (default: %(default)s)"
    )
    add(
        "notarise",
        cmd_notarise,
        "Developer ID sign, notarise and staple an app",
        *(app, identity, entitlements, signing, notary, dry),
    )
    add("dmg", cmd_dmg, "package a signed app into a notarised DMG", app, identity, notary, out, dry)
    add(
        "release",
        cmd_release,
        "notarise an app, package it into a notarised DMG, then verify both",
        *(app, identity, entitlements, signing, notary, out, dry),
    )
    sub = add("verify", cmd_verify, "check signatures, hardened runtime, Gatekeeper and staples", app, entitlements)
    sub.add_argument("dmg", type=existing_file, nargs="?", help="a DMG to check as well")
    sub = add("history", cmd_history, "list submissions to Apple, or show the log of one", notary)
    sub.add_argument("id", nargs="?", help="submission ID")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Turned into an exception so that temporary files and mounted images are cleaned up.
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, lambda received, _: sys.exit(128 + received))
    try:
        args.run(Shell(getattr(args, "dry_run", False)), args)
    except Failure as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
