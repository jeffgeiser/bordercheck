"""#7: compressed and encoded data is found from its contents, not its file name; formats
bordercheck can't decode are errors, never a silent clean."""
import base64
import bz2
import gzip
import json
import lzma
import os
import sys
import tempfile
import unittest
from unittest import mock

from bordercheck import canary, scan
from test_bordercheck import scan_one

NEEDLE = (("canary", "canary", b"CNRY-TEST-0001"),)
TEXT = b"2026-10-09 INFO ask prompt=ref CNRY-TEST-0001\n"


def zstd_frame(data):
    """A minimal valid zstd frame: one raw (uncompressed) block, so no encoder is needed."""
    assert len(data) < 256
    block = 1 | (len(data) << 3)               # last block, type raw, size
    return b"\x28\xb5\x2f\xfd" + bytes([0x20, len(data)]) + block.to_bytes(3, "little") + data


def zstd_available():
    return scan._zstd_decompressor() is not None or scan.shutil.which("zstd") is not None


class FormatTests(unittest.TestCase):
    def scan_file(self, data, name="x.log", needles=NEEDLE):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
            return scan_one({"type": "path", "path": d}, needles)

    def test_gzip_without_a_gz_name_is_found(self):
        res = self.scan_file(gzip.compress(TEXT), "app.log.1")
        self.assertEqual((len(res["hits"]), res["errors"]), (1, []))

    def test_concatenated_gzip_members_are_all_searched(self):
        res = self.scan_file(gzip.compress(b"first member\n") + gzip.compress(TEXT))
        self.assertEqual(len(res["hits"]), 1)

    def test_large_expansion_is_searched_in_pieces(self):
        """20 MB of zeros compresses to a few KB; the canary at the very end must still be found,
        with every decompress call capped at one chunk."""
        big = b"\x00" * (20 << 20) + TEXT
        for compress in (gzip.compress, bz2.compress, lzma.compress):
            sizes = []
            real = scan.scan_stream

            def watch(chunks, *a):
                def sized():
                    for c in chunks:
                        sizes.append(len(c))
                        yield c
                return real(sized(), *a)

            with mock.patch.object(scan, "scan_stream", watch):
                res = self.scan_file(compress(big))
            self.assertEqual(len(res["hits"]), 1, compress.__module__)
            self.assertLessEqual(max(sizes), scan.CHUNK, compress.__module__)

    def test_bzip2_and_xz_are_found(self):
        for data in (bz2.compress(TEXT), lzma.compress(TEXT)):
            res = self.scan_file(data)
            self.assertEqual((len(res["hits"]), res["errors"]), (1, []))

    def test_command_output_that_is_gzip_is_found(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "export.bin")
            with open(path, "wb") as f:
                f.write(gzip.compress(TEXT))
            res = scan_one({"type": "command", "command": f"cat {path}"}, NEEDLE)
        self.assertEqual((len(res["hits"]), res["errors"]), (1, []))

    @unittest.skipUnless(zstd_available(), "needs Python 3.14+ or the zstd command")
    def test_zstd_is_decoded_when_a_decoder_is_available(self):
        res = self.scan_file(zstd_frame(b"other\n") + zstd_frame(TEXT))
        self.assertEqual((len(res["hits"]), res["errors"]), (1, []))

    def test_zstd_command_fallback(self):
        """Without compression.zstd, the zstd command is used. A stand-in `zstd` that decodes the
        raw-block frames above exercises that path on every Python."""
        fake = (f"#!{sys.executable}\n"
                "import sys\n"
                "data, out = sys.stdin.buffer.read(), sys.stdout.buffer\n"
                "while data:\n"
                "    if data[:4] != b'\\x28\\xb5\\x2f\\xfd' or len(data) < 9: sys.exit(1)\n"
                "    size = int.from_bytes(data[6:9], 'little') >> 3\n"
                "    out.write(data[9:9 + size]); data = data[9 + size:]\n")
        with tempfile.TemporaryDirectory() as bindir:
            path = os.path.join(bindir, "zstd")
            with open(path, "w") as f:
                f.write(fake)
            os.chmod(path, 0o755)
            env = {"PATH": bindir + os.pathsep + os.environ.get("PATH", "")}
            with mock.patch.object(scan, "_zstd_decompressor", return_value=None), mock.patch.dict(os.environ, env):
                good = self.scan_file(zstd_frame(b"other\n") + zstd_frame(TEXT))
                bad = self.scan_file(zstd_frame(TEXT)[:4] + b"\x20")
        self.assertEqual((len(good["hits"]), good["errors"]), (1, []))
        self.assertIn("zstd data is corrupt", bad["errors"][0])

    def test_zstd_without_a_decoder_is_an_error_not_clean(self):
        with mock.patch.object(scan, "_zstd_decompressor", return_value=None), \
                mock.patch.object(scan.shutil, "which", return_value=None):
            res = self.scan_file(zstd_frame(TEXT))
        self.assertEqual(res["targets_scanned"], 0)
        self.assertIn("zstd-compressed data found but no decoder", res["errors"][0])

    def test_formats_it_cannot_decode_are_errors(self):
        for magic, name in ((b"PAR1", "Parquet"), (b"\xff\x06\x00\x00sNaPpY", "Snappy-framed"),
                            (b"\x04\x22\x4d\x18", "LZ4")):
            res = self.scan_file(magic + b"\x00" * 32 + b"CNRY-TEST-0001", "part-0000")
            self.assertEqual(res["targets_scanned"], 0, name)
            self.assertIn(f"{name} data: bordercheck can't decode this format", res["errors"][0])
            self.assertNotIn("CNRY", json.dumps(res["errors"]))

    def test_case_and_json_escape_variants_are_found(self):
        rec = canary.new_record()
        local, domain = rec["email"].split("@")
        phone = rec["phone"].replace(" ", "")
        variants = {
            "email": [rec["email"].upper(), local + "\\u0040" + domain,
                      ".".join(p.capitalize() for p in local.split(".")) + "@" + domain],
            "iban": [rec["iban"].lower(), " ".join(rec["iban"].lower()[i:i + 4] for i in range(0, 22, 4))],
            "phone": ["\\u002b" + phone[1:]],
            "canary": [rec["canary"].replace("-", "\\u002d")],
        }
        needles = canary.needles(rec, "run-x")
        for kind, texts in variants.items():
            for text in texts:
                hits, _ = scan.scan_stream([f"x {text} y".encode()], needles, [])
                self.assertIn(kind, {h["kind"] for h in hits}, text)

    def test_base64_inside_gzip_is_found(self):
        rec = canary.new_record()
        payload = json.dumps({"payload": base64.b64encode(f"iban {rec['iban']}".encode()).decode()}).encode()
        res = self.scan_file(gzip.compress(payload), needles=canary.needles(rec, "run-x"))
        self.assertIn("iban", {h["kind"] for h in res["hits"]})


if __name__ == "__main__":
    unittest.main()
