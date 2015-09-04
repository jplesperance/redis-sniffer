import unittest
from redis_sniffer.sniffer import Sniffer

class TestClass(unittest.TestCase):
    def test_version(self):
        self.assertEqual(Sniffer.version(), "v1.1.0")


if __name__ == "__main__":
    unittest.main()


