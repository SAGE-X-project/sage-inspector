"""SESSION-01 fixtures retain source and transcript relations."""

import unittest

import check_current_spec_session01_vectors as checker


class Session01VectorTests(unittest.TestCase):
    def test_session_id_and_tuple_scenarios(self):
        self.assertEqual(checker.check(), 8)


if __name__ == '__main__':
    unittest.main()
