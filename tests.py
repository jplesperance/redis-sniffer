import unittest
from redis_sniffer import sniffer

class TestClass(unittest.TestCase):
    def test_version(self):
        self.assertEqual(sniffer.version(), "v1.0.0")


if __name__ == "__main__":
    unittest.main()


