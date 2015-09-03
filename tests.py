import unittest
import redis_sniffer.sniffer

class TestClass(unittest.TestCase):
    def test_version(self):
        self.assertEqual(sniffer.version(), "v1.0.0")


if __name__ == "__main__":
    unittest.main()


