"""The fixed six-phase plan leaves no unbound current-spec track."""

import unittest

from check_current_spec_all_bindings import check


class AllBindingsTests(unittest.TestCase):
    def test_every_parent_track_and_child_is_bound(self):
        self.assertEqual(check(), {'parent_cases': 481,
                                   'mandatory_children': 26,
                                   'required_tracks': 554,
                                   'complete_bindings': 0})


if __name__ == '__main__':
    unittest.main()
