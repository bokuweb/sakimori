"""Check the archive contract without executing release binaries."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("licenses", Path(__file__).with_name("check-release-licenses.py"))
licenses = importlib.util.module_from_spec(spec)
spec.loader.exec_module(licenses)


class ReleaseLicenseTests(unittest.TestCase):
    def archive(self, directory, entries):
        archive = Path(directory) / "candidate.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, data in entries:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        return archive

    def entries(self, target="aarch64-apple-darwin"):
        prefix = "sakimori-" + target
        return [(f"{prefix}/{name}", (licenses.ROOT / name).read_bytes()) for name in licenses.NAMES]

    def test_distributable_crates_include_complete_source_licenses(self):
        for manifest in (licenses.ROOT / "crates").glob("*/Cargo.toml"):
            for name in licenses.NAMES:
                self.assertEqual((manifest.parent / name).read_bytes(), (licenses.ROOT / name).read_bytes(), f"{manifest.parent.name}/{name}")

    def test_all_platform_archives_require_both_complete_texts(self):
        for target in ["aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "x86_64-pc-windows-msvc"]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                licenses.check(self.archive(directory, self.entries(target)))

    def test_missing_license_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "LICENSE-APACHE"):
                licenses.check(self.archive(directory, self.entries()[:1]))

    def test_truncated_or_changed_text_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            entries = self.entries()
            entries[0] = (entries[0][0], b"MIT")
            with self.assertRaisesRegex(ValueError, "text"):
                licenses.check(self.archive(directory, entries))

    def test_duplicate_or_nested_license_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            entries = self.entries()
            for invalid in [entries + entries[:1], [("nested/" + name, data) for name, data in entries]]:
                with self.assertRaises(ValueError):
                    licenses.check(self.archive(directory, invalid))


if __name__ == "__main__":
    unittest.main()
