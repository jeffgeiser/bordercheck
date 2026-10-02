import base64
import os
import tempfile
import unittest

from canarykit import canary, config, scan


class CanaryTests(unittest.TestCase):
    def test_base64_found_at_every_alignment(self):
        rec = canary.new_record()
        cores = [n[2] for n in canary.needles(rec, "run-x") if "base64" in n[1]]
        for prefix in (b"", b"a", b"ab", b"abc", b"abcd"):
            encoded = base64.b64encode(prefix + rec["canary"].encode() + b" trailing text")
            self.assertTrue(any(c in encoded for c in cores), prefix)

    def test_values_are_unique(self):
        a, b = canary.new_record(), canary.new_record()
        self.assertNotEqual(a["canary"], b["canary"])
        self.assertTrue(a["synthetic"])


class ScanTests(unittest.TestCase):
    def test_match_across_chunk_boundary_reports_correct_line(self):
        needle = b"CNRY-ABCD-EFGH"
        data = b"x\n" * 10 + b"y" * (scan.CHUNK - 25) + needle + b"\nend"
        chunks = [data[i:i + scan.CHUNK] for i in range(0, len(data), scan.CHUNK)]
        hits, _ = scan.scan_stream(chunks, [("canary", "canary", needle)], [])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["line"], 11)
        self.assertEqual(hits[0]["offset"], data.find(needle))

    def test_watch_wildcards(self):
        rx = scan._watch_regex("bedrock-runtime.*.amazonaws.com")
        self.assertTrue(rx.search(b"CONNECT bedrock-runtime.eu-central-1.amazonaws.com:443"))
        self.assertFalse(rx.search(b"CONNECT s3.amazonaws.com:443"))

    def test_missing_path_is_an_error_not_clean(self):
        cfg = {"watch_destinations": [], "sources": [
            {"name": "gone", "type": "path", "path": "/nonexistent/xyz", "layer": "logs", "location": "DE"}]}
        res = scan.scan_sources(cfg, [("canary", "canary", b"CNRY")])
        self.assertTrue(res[0]["errors"])


class ConfigTests(unittest.TestCase):
    def _write(self, env):
        f = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        f.write(f'environment = "{env}"\n[border]\nallowed_locations=["DE"]\n'
                '[target]\nurl="http://x"\nbody="{{{{prompt}}}}"\nprompt="hi"\n')
        f.close()
        return f.name

    def test_refuses_production(self):
        path = self._write("production")
        with self.assertRaises(config.ConfigError):
            config.load(path)
        self.assertEqual(config.load(path, allow_production=True)["environment"], "production")
        os.unlink(path)

    def test_missing_env_var_is_an_error(self):
        os.environ.pop("CK_DEFINITELY_UNSET", None)
        with self.assertRaises(config.ConfigError):
            config.expand_env("Bearer ${CK_DEFINITELY_UNSET}")


if __name__ == "__main__":
    unittest.main()
