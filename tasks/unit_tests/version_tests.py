import os
import random
import unittest
from unittest.mock import MagicMock, patch

from invoke import MockContext, Result

from tasks.libs.releasing.version import (
    current_version_for_release_branch,
    get_matching_pattern,
    next_rc_version,
    query_version,
)
from tasks.libs.types.version import Version


class TestVersionComparison(unittest.TestCase):
    def _get_version(self, major, minor, patch, rc, devel):
        return Version(major, minor, patch=patch, rc=rc, devel=devel)

    def _get_random_version(self):
        return self._get_version(
            random.randint(0, 99),
            random.randint(0, 99),
            random.randint(0, 99),
            # For tests, rc must be non-0, as 0 signifies a release version, which would
            # break some tests like test_rc_higher and test_rc_lower
            random.randint(1, 99),
            random.choice([True, False]),
        )

    def test_major_lower(self):
        version = self._get_random_version()
        increment = random.randint(1, 99)
        self.assertFalse(
            self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
            > self._get_version(version.major + increment, version.minor, version.patch, version.rc, version.devel)
        )

    def test_major_higher(self):
        version = self._get_random_version()
        increment = random.randint(1, 99)
        self.assertTrue(
            self._get_version(version.major + increment, version.minor, version.patch, version.rc, version.devel)
            > self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
        )

    def test_minor_lower(self):
        version = self._get_random_version()
        increment = random.randint(1, 99)
        self.assertFalse(
            self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
            > self._get_version(version.major, version.minor + increment, version.patch, version.rc, version.devel)
        )

    def test_minor_higher(self):
        version = self._get_random_version()
        increment = random.randint(1, 99)
        self.assertTrue(
            self._get_version(version.major, version.minor + increment, version.patch, version.rc, version.devel)
            > self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
        )

    def test_patch_lower(self):
        version = self._get_random_version()
        increment = random.randint(1, 99)
        self.assertFalse(
            self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
            > self._get_version(version.major, version.minor, version.patch + increment, version.rc, version.devel)
        )

    def test_patch_higher(self):
        version = self._get_random_version()
        increment = random.randint(1, 99)
        self.assertTrue(
            self._get_version(version.major, version.minor, version.patch + increment, version.rc, version.devel)
            > self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
        )

    def test_rc_lower_than_release(self):
        version = self._get_random_version()
        self.assertFalse(
            self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
            > self._get_version(version.major, version.minor, version.patch, None, version.devel)
        )

    def test_release_higher_than_rc(self):
        version = self._get_random_version()
        self.assertTrue(
            self._get_version(version.major, version.minor, version.patch, None, version.devel)
            > self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
        )

    def test_rc_lower(self):
        version = self._get_random_version()
        increment = random.randint(1, 99)
        self.assertFalse(
            self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
            > self._get_version(version.major, version.minor, version.patch, version.rc + increment, version.devel)
        )

    def test_rc_higher(self):
        version = self._get_random_version()
        increment = random.randint(1, 99)
        self.assertTrue(
            self._get_version(version.major, version.minor, version.patch, version.rc + increment, version.devel)
            > self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
        )

    def test_equal(self):
        version = self._get_random_version()
        self.assertFalse(
            self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
            > self._get_version(version.major, version.minor, version.patch, version.rc, version.devel)
        )

    def test_absent_patch_equal_zero(self):
        version = self._get_random_version()
        self.assertFalse(
            self._get_version(version.major, version.minor, None, None, version.devel)
            > self._get_version(version.major, version.minor, 0, None, version.devel)
        )

    def test_absent_patch_less_than_any(self):
        version = self._get_random_version()
        increment = random.randint(1, 99)
        self.assertTrue(
            self._get_version(version.major, version.minor, version.patch + increment, None, version.devel)
            > self._get_version(version.major, version.minor, None, None, version.devel)
        )

    def test_devel_less_than_any(self):
        version = self._get_random_version()
        self.assertTrue(
            self._get_version(version.major, version.minor, version.patch, None, False)
            > self._get_version(version.major, version.minor, version.patch, None, True)
        )

    def test_devel_less_than_rc(self):
        version = self._get_random_version()
        self.assertTrue(
            self._get_version(version.major, version.minor, version.patch, version.rc, False)
            > self._get_version(version.major, version.minor, version.patch, None, True)
        )

    def test_devel_equal(self):
        version = self._get_random_version()
        self.assertTrue(
            self._get_version(version.major, version.minor, version.patch, None, True)
            == self._get_version(version.major, version.minor, version.patch, None, True)
        )


class TestNonDevelVersion(unittest.TestCase):
    version = Version(major=1, minor=0, devel=True)

    def test_non_devel_version(self):
        new_version = self.version.non_devel_version()
        expected_version = Version(major=1, minor=0)  # 1.0.0

        self.assertEqual(new_version, expected_version)


class TestNextVersion(unittest.TestCase):
    version = Version(major=1, minor=0)

    def test_next_version_major(self):
        new_version = self.version.next_version(bump_major=True)
        expected_version = Version(major=2, minor=0)

        self.assertEqual(new_version, expected_version)

    def test_next_version_minor(self):
        new_version = self.version.next_version(bump_minor=True)
        expected_version = Version(major=1, minor=1)

        self.assertEqual(new_version, expected_version)

    def test_next_version_patch(self):
        new_version = self.version.next_version(bump_patch=True)
        expected_version = Version(major=1, minor=0, patch=1)

        self.assertEqual(new_version, expected_version)

    def test_next_version_major_rc(self):
        new_version = self.version.next_version(bump_major=True, rc=True)
        expected_version = Version(major=2, minor=0, rc=1)

        self.assertEqual(new_version, expected_version)

    def test_next_version_minor_rc(self):
        new_version = self.version.next_version(bump_minor=True, rc=True)
        expected_version = Version(major=1, minor=1, rc=1)

        self.assertEqual(new_version, expected_version)

    def test_next_version_patch_rc(self):
        new_version = self.version.next_version(bump_patch=True, rc=True)
        expected_version = Version(major=1, minor=0, patch=1, rc=1)

        self.assertEqual(new_version, expected_version)

    def test_next_version_rc(self):
        version = self.version.next_version(bump_patch=True, rc=True)  # 1.0.1-rc.1
        new_version = version.next_version(rc=True)
        expected_version = Version(major=1, minor=0, patch=1, rc=2)

        self.assertEqual(new_version, expected_version)

    def test_next_version_promote_rc(self):
        version = self.version.next_version(bump_patch=True, rc=True)  # 1.0.1-rc.1
        new_version = version.next_version(rc=False)
        expected_version = Version(major=1, minor=0, patch=1)

        self.assertEqual(new_version, expected_version)


class TestPreviousRCVersion(unittest.TestCase):
    def test_non_rc(self):
        version = Version(major=1, minor=1)
        with self.assertRaises(RuntimeError):
            version.previous_rc_version()

    def test_rc_1_no_patch(self):
        version = Version(major=1, minor=1, rc=1)
        with self.assertRaises(RuntimeError):
            version.previous_rc_version()

    def test_rc_1(self):
        version = Version(major=1, minor=1, patch=1, rc=1)
        previous = str(version.previous_rc_version())
        self.assertEqual(previous, "1.1.1-devel")

    def test_rc_42(self):
        version = Version(major=1, minor=1, patch=1, rc=42)
        previous = str(version.previous_rc_version())
        self.assertEqual(previous, "1.1.1-rc.41")


class TestQALabel(unittest.TestCase):
    expected = "1.2.0-qa"

    def test_minor_major(self):
        v = Version(1, 2)
        self.assertEqual(v.qa_label(), self.expected)

    def test_minor_major_patch(self):
        v = Version(1, 2, patch=0)
        self.assertEqual(v.qa_label(), self.expected)

    def test_minor_major_patch_devel(self):
        v = Version(1, 2, devel=True)
        self.assertEqual(v.qa_label(), self.expected)

    def test_minor_major_patch_rc(self):
        v = Version(1, 2, rc=1)
        self.assertEqual(v.qa_label(), self.expected)


class TestQueryVersion(unittest.TestCase):
    @patch.dict(os.environ, {"BUCKET_BRANCH": "dev"}, clear=True)
    def test_on_dev_bucket(self):
        major_version = "7"
        c = MockContext(
            run={
                r'git describe --tags --candidates=50 --match "7\.*" --abbrev=7': Result(
                    "7.54.0-dbm-mongo-0.1-163-g315e3a2"
                )
            }
        )
        v, p, c, g, _ = query_version(c, major_version)
        self.assertEqual(v, "7.54.0")
        self.assertEqual(p, "dbm-mongo-0.1")
        self.assertEqual(c, 163)
        self.assertEqual(g, "315e3a2")

    @patch.dict(os.environ, {"BUCKET_BRANCH": "nightly"}, clear=True)
    def test_on_nightly_bucket(self):
        major_version = "7"
        c = MockContext(
            run={
                "git rev-parse --abbrev-ref HEAD": Result("main"),
                rf"git tag --list --merged main | grep -E '^{major_version}\.[0-9]+\.[0-9]+(-rc.*|-devel.*)?$'": Result(
                    "7.55.0-devel"
                ),
                'git describe --tags --candidates=50 --match "7.55.0-devel" --abbrev=7': Result(
                    "7.55.0-devel-543-g315e3a2"
                ),
            }
        )
        v, p, c, g, _ = query_version(c, major_version)
        self.assertEqual(v, "7.55.0")
        self.assertEqual(p, "devel")
        self.assertEqual(c, 543)
        self.assertEqual(g, "315e3a2")

    def test_on_release(self):
        major_version = "7"
        c = MockContext(
            run={
                "git rev-parse --abbrev-ref HEAD": Result("7.55.x"),
                rf"git tag --list --merged 7.55.x | grep -E '^{major_version}\.[0-9]+\.[0-9]+(-rc.*|-devel.*)?$'": Result(
                    "7.55.0-devel"
                ),
                'git describe --tags --candidates=50 --match "7.55.0-devel" --abbrev=7': Result(
                    "7.55.0-devel-543-g315e3a2"
                ),
            }
        )
        v, p, c, g, _ = query_version(c, major_version, release=True)
        self.assertEqual(v, "7.55.0")
        self.assertEqual(p, "devel")
        self.assertEqual(c, 543)
        self.assertEqual(g, "315e3a2")


@patch("os.environ", {"BUCKET_BRANCH": "dev"})
class TestGetMatchingPattern(unittest.TestCase):
    def test_on_patch_release(self):
        c = MockContext(
            run={
                "git rev-parse --abbrev-ref HEAD": Result("7.55.x"),
                r"git tag --list --merged 7.55.x | grep -E '^7\.[0-9]+\.[0-9]+(-rc.*|-devel.*)?$'": Result(
                    '7.15.0-devel\n7.15.0-rc.2\n7.15.0-rc.4\n7.15.0-rc.5\n7.15.0-rc.6\n7.15.0-rc.7\n7.15.0-rc.8\n7.15.0-rc.9\n7.16.0\n7.16.0-rc.1\n7.16.0-rc.2\n7.16.0-rc.3\n7.16.0-rc.4\n7.16.0-rc.5\n7.16.0-rc.6\n7.16.0-rc.7\n7.16.0-rc.8\n7.16.0-rc.9\n7.17.0-devel\n7.17.0-rc.1\n7.17.0-rc.2\n7.17.0-rc.3\n7.17.0-rc.4\n7.18.0-devel\n7.18.0-rc.1\n7.18.0-rc.2\n7.18.0-rc.3\n7.18.0-rc.4\n7.18.0-rc.5\n7.18.0-rc.6\n7.19.0-devel\n7.19.0-rc.1\n7.19.0-rc.2\n7.19.0-rc.3\n7.19.0-rc.4\n7.19.0-rc.5\n7.20.0-devel\n7.20.0-rc.1\n7.20.0-rc.2\n7.20.0-rc.3\n7.20.0-rc.4\n7.20.0-rc.5\n7.20.0-rc.6\n7.20.0-rc.7\n7.21.0-devel\n7.21.0-rc.1\n7.21.0-rc.2\n7.21.0-rc.3\n7.22.0-devel\n7.22.0-rc.1\n7.22.0-rc.2\n7.22.0-rc.3\n7.22.0-rc.4\n7.22.0-rc.5\n7.22.0-rc.6\n7.23.0-devel\n7.23.0-rc.1\n7.23.0-rc.2\n7.23.0-rc.3\n7.24.0-devel\n7.24.0-rc.1\n7.24.0-rc.2\n7.24.0-rc.3\n7.24.0-rc.4\n7.24.0-rc.5\n7.25.0-devel\n7.25.0-rc.1\n7.25.0-rc.2\n7.25.0-rc.3\n7.25.0-rc.4\n7.25.0-rc.5\n7.25.0-rc.6\n7.26.0-devel\n7.26.0-rc.1\n7.26.0-rc.2\n7.26.0-rc.3\n7.27.0-devel\n7.27.0-rc.1\n7.27.0-rc.2\n7.27.0-rc.3\n7.27.0-rc.4\n7.27.0-rc.5\n7.27.0-rc.6\n7.28.0-devel\n7.28.0-rc.1\n7.28.0-rc.2\n7.28.0-rc.3\n7.29.0-devel\n7.29.0-rc.1\n7.29.0-rc.2\n7.29.0-rc.3\n7.29.0-rc.4\n7.29.0-rc.5\n7.29.0-rc.6\n7.30.0-devel\n7.30.0-rc.1\n7.30.0-rc.2\n7.30.0-rc.3\n7.30.0-rc.4\n7.30.0-rc.5\n7.30.0-rc.6\n7.30.0-rc.7\n7.31.0-devel\n7.31.0-rc.1\n7.31.0-rc.2\n7.31.0-rc.3\n7.31.0-rc.4\n7.31.0-rc.5\n7.31.0-rc.6\n7.31.0-rc.7\n7.31.0-rc.8\n7.32.0-devel\n7.32.0-rc.1\n7.32.0-rc.2\n7.32.0-rc.3\n7.32.0-rc.4\n7.32.0-rc.5\n7.32.0-rc.6\n7.33.0-devel\n7.33.0-rc.1\n7.33.0-rc.2\n7.33.0-rc.3\n7.33.0-rc.4\n7.33.0-rc.4-dbm-beta-0.1\n7.34.0-devel\n7.34.0-rc.1\n7.34.0-rc.2\n7.34.0-rc.3\n7.34.0-rc.4\n7.35.0-devel\n7.35.0-rc.1\n7.35.0-rc.2\n7.35.0-rc.3\n7.35.0-rc.4\n7.36.0-devel\n7.36.0-rc.1\n7.36.0-rc.2\n7.36.0-rc.3\n7.36.0-rc.4\n7.37.0-devel\n7.37.0-rc.1\n7.37.0-rc.2\n7.37.0-rc.3\n7.38.0-devel\n7.38.0-rc.1\n7.38.0-rc.2\n7.38.0-rc.3\n7.39.0-devel\n7.39.0-rc.1\n7.39.0-rc.2\n7.39.0-rc.3\n7.40.0-devel\n7.40.0-rc.1\n7.40.0-rc.2\n7.41.0-devel\n7.41.0-rc.1\n7.41.0-rc.2\n7.41.0-rc.3\n7.42.0-devel\n7.42.0-rc.1\n7.42.0-rc.2\n7.42.0-rc.3\n7.43.0-devel\n7.43.0-rc.1\n7.43.0-rc.2\n7.43.0-rc.3\n7.44.0-devel\n7.44.0-rc.1\n7.44.0-rc.2\n7.44.0-rc.3\n7.44.0-rc.4\n7.45.0-devel\n7.45.0-rc.1\n7.45.0-rc.2\n7.45.0-rc.3\n7.46.0-devel\n7.46.0-rc.1\n7.46.0-rc.2\n7.47.0-devel\n7.47.0-rc.1\n7.47.0-rc.2\n7.47.0-rc.3\n7.48.0-devel\n7.48.0-rc.0\n7.48.0-rc.1\n7.48.0-rc.2\n7.49.0-devel\n7.49.0-rc.1\n7.49.0-rc.2\n7.50.0-devel\n7.50.0-rc.1\n7.50.0-rc.2\n7.50.0-rc.3\n7.50.0-rc.4\n7.51.0-devel\n7.51.0-rc.1\n7.51.0-rc.2\n7.52.0-devel\n7.52.0-rc.1\n7.52.0-rc.2\n7.52.0-rc.3\n7.53.0-devel\n7.53.0-rc.1\n7.53.0-rc.2\n7.54.0-devel\n7.54.0-rc.1\n7.54.0-rc.2\n7.55.0\n7.55.0-devel\n7.55.0-rc.1\n7.55.0-rc.10\n7.55.0-rc.11\n7.55.0-rc.2\n7.55.0-rc.3\n7.55.0-rc.4\n7.55.0-rc.5\n7.55.0-rc.6\n7.55.0-rc.7\n7.55.0-rc.8\n7.55.0-rc.9'
                ),
            }
        )
        self.assertEqual(get_matching_pattern(c, major_version="7", release=True), "7.55.0")

    def test_on_release(self):
        c = MockContext(
            run={
                "git rev-parse --abbrev-ref HEAD": Result("7.55.x"),
                r"git tag --list --merged 7.55.x | grep -E '^7\.[0-9]+\.[0-9]+(-rc.*|-devel.*)?$'": Result(
                    '7.15.0-devel\n7.15.0-rc.2\n7.15.0-rc.4\n7.15.0-rc.5\n7.15.0-rc.6\n7.15.0-rc.7\n7.15.0-rc.8\n7.15.0-rc.9\n7.16.0\n7.16.0-rc.1\n7.16.0-rc.2\n7.16.0-rc.3\n7.16.0-rc.4\n7.16.0-rc.5\n7.16.0-rc.6\n7.16.0-rc.7\n7.16.0-rc.8\n7.16.0-rc.9\n7.17.0-devel\n7.17.0-rc.1\n7.17.0-rc.2\n7.17.0-rc.3\n7.17.0-rc.4\n7.18.0-devel\n7.18.0-rc.1\n7.18.0-rc.2\n7.18.0-rc.3\n7.18.0-rc.4\n7.18.0-rc.5\n7.18.0-rc.6\n7.19.0-devel\n7.19.0-rc.1\n7.19.0-rc.2\n7.19.0-rc.3\n7.19.0-rc.4\n7.19.0-rc.5\n7.20.0-devel\n7.20.0-rc.1\n7.20.0-rc.2\n7.20.0-rc.3\n7.20.0-rc.4\n7.20.0-rc.5\n7.20.0-rc.6\n7.20.0-rc.7\n7.21.0-devel\n7.21.0-rc.1\n7.21.0-rc.2\n7.21.0-rc.3\n7.22.0-devel\n7.22.0-rc.1\n7.22.0-rc.2\n7.22.0-rc.3\n7.22.0-rc.4\n7.22.0-rc.5\n7.22.0-rc.6\n7.23.0-devel\n7.23.0-rc.1\n7.23.0-rc.2\n7.23.0-rc.3\n7.24.0-devel\n7.24.0-rc.1\n7.24.0-rc.2\n7.24.0-rc.3\n7.24.0-rc.4\n7.24.0-rc.5\n7.25.0-devel\n7.25.0-rc.1\n7.25.0-rc.2\n7.25.0-rc.3\n7.25.0-rc.4\n7.25.0-rc.5\n7.25.0-rc.6\n7.26.0-devel\n7.26.0-rc.1\n7.26.0-rc.2\n7.26.0-rc.3\n7.27.0-devel\n7.27.0-rc.1\n7.27.0-rc.2\n7.27.0-rc.3\n7.27.0-rc.4\n7.27.0-rc.5\n7.27.0-rc.6\n7.28.0-devel\n7.28.0-rc.1\n7.28.0-rc.2\n7.28.0-rc.3\n7.29.0-devel\n7.29.0-rc.1\n7.29.0-rc.2\n7.29.0-rc.3\n7.29.0-rc.4\n7.29.0-rc.5\n7.29.0-rc.6\n7.30.0-devel\n7.30.0-rc.1\n7.30.0-rc.2\n7.30.0-rc.3\n7.30.0-rc.4\n7.30.0-rc.5\n7.30.0-rc.6\n7.30.0-rc.7\n7.31.0-devel\n7.31.0-rc.1\n7.31.0-rc.2\n7.31.0-rc.3\n7.31.0-rc.4\n7.31.0-rc.5\n7.31.0-rc.6\n7.31.0-rc.7\n7.31.0-rc.8\n7.32.0-devel\n7.32.0-rc.1\n7.32.0-rc.2\n7.32.0-rc.3\n7.32.0-rc.4\n7.32.0-rc.5\n7.32.0-rc.6\n7.33.0-devel\n7.33.0-rc.1\n7.33.0-rc.2\n7.33.0-rc.3\n7.33.0-rc.4\n7.33.0-rc.4-dbm-beta-0.1\n7.34.0-devel\n7.34.0-rc.1\n7.34.0-rc.2\n7.34.0-rc.3\n7.34.0-rc.4\n7.35.0-devel\n7.35.0-rc.1\n7.35.0-rc.2\n7.35.0-rc.3\n7.35.0-rc.4\n7.36.0-devel\n7.36.0-rc.1\n7.36.0-rc.2\n7.36.0-rc.3\n7.36.0-rc.4\n7.37.0-devel\n7.37.0-rc.1\n7.37.0-rc.2\n7.37.0-rc.3\n7.38.0-devel\n7.38.0-rc.1\n7.38.0-rc.2\n7.38.0-rc.3\n7.39.0-devel\n7.39.0-rc.1\n7.39.0-rc.2\n7.39.0-rc.3\n7.40.0-devel\n7.40.0-rc.1\n7.40.0-rc.2\n7.41.0-devel\n7.41.0-rc.1\n7.41.0-rc.2\n7.41.0-rc.3\n7.42.0-devel\n7.42.0-rc.1\n7.42.0-rc.2\n7.42.0-rc.3\n7.43.0-devel\n7.43.0-rc.1\n7.43.0-rc.2\n7.43.0-rc.3\n7.44.0-devel\n7.44.0-rc.1\n7.44.0-rc.2\n7.44.0-rc.3\n7.44.0-rc.4\n7.45.0-devel\n7.45.0-rc.1\n7.45.0-rc.2\n7.45.0-rc.3\n7.46.0-devel\n7.46.0-rc.1\n7.46.0-rc.2\n7.47.0-devel\n7.47.0-rc.1\n7.47.0-rc.2\n7.47.0-rc.3\n7.48.0-devel\n7.48.0-rc.0\n7.48.0-rc.1\n7.48.0-rc.2\n7.49.0-devel\n7.49.0-rc.1\n7.49.0-rc.2\n7.50.0-devel\n7.50.0-rc.1\n7.50.0-rc.2\n7.50.0-rc.3\n7.50.0-rc.4\n7.51.0-devel\n7.51.0-rc.1\n7.51.0-rc.2\n7.52.0-devel\n7.52.0-rc.1\n7.52.0-rc.2\n7.52.0-rc.3\n7.53.0-devel\n7.53.0-rc.1\n7.53.0-rc.2\n7.54.0-devel\n7.54.0-rc.1\n7.54.0-rc.2\n7.55.0-devel\n7.55.0-rc.1\n7.55.0-rc.10\n7.55.0-rc.11\n7.55.0-rc.2\n7.55.0-rc.3\n7.55.0-rc.4\n7.55.0-rc.5\n7.55.0-rc.6\n7.55.0-rc.7\n7.55.0-rc.8\n7.55.0-rc.9'
                ),
            }
        )
        self.assertEqual(get_matching_pattern(c, major_version="7", release=True), "7.55.0-rc.11")

    def test_on_branch(self):
        c = MockContext(run={})
        self.assertEqual(get_matching_pattern(c, major_version="42", release=False), r"42\.*")
        c.run.assert_not_called()


class TestFromTag(unittest.TestCase):
    def test_tags_standard(self):
        tag = "7.62.1"
        expected = Version(7, 62, 1)

        v = Version.from_tag(tag)
        self.assertEqual(v, expected)

    def test_tags_prefix(self):
        tag = "pref-7.62.1"
        expected = Version(7, 62, 1, prefix='pref-')

        v = Version.from_tag(tag)
        self.assertEqual(v, expected)

    def test_tags_rc(self):
        tag = "6.53.0-rc.10"
        expected = Version(6, 53, 0, rc=10)

        v = Version.from_tag(tag)
        self.assertEqual(v, expected)

    def test_tags_devel(self):
        tag = "7.64.0-devel"
        expected = Version(7, 64, 0, devel=True)

        v = Version.from_tag(tag)
        self.assertEqual(v, expected)


class TestCurrentVersionForReleaseBranch(unittest.TestCase):
    def test_simple(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0-rc.1\n7.63.0"
        version = current_version_for_release_branch(ctx, '7.63.x')

        self.assertEqual(version, Version(7, 63, 0))

    def test_rc_version(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0-rc.1\n7.63.0-rc.2"
        version = current_version_for_release_branch(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 63, 0, rc=2))

    def test_rc_version_sorted(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0-rc.2\n7.63.0-rc.1"
        version = current_version_for_release_branch(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 63, 0, rc=2))

    def test_rc_version_sorted_hard(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0-rc.10\n7.63.0-rc.2"
        version = current_version_for_release_branch(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 63, 0, rc=10))

    def test_next_rc_version(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0\n7.63.1-rc.1"
        version = current_version_for_release_branch(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 63, 1, rc=1))

    def test_next_release_version(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0\n7.63.1-rc.1\n7.63.1"
        version = current_version_for_release_branch(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 63, 1))

    def test_first_rc_version(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0-devel"
        version = current_version_for_release_branch(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 63, 0, devel=True))


class TestNextVersionForReleaseBranch(unittest.TestCase):
    def test_simple(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0-rc.1\n7.63.0"
        version = next_rc_version(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 64, 0, rc=1))

    def test_rc_version(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0-rc.1\n7.63.0-rc.2"
        version = next_rc_version(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 63, 0, rc=3))

    def test_rc_version_sorted(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0-rc.2\n7.63.0-rc.1"
        version = next_rc_version(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 63, 0, rc=3))

    def test_rc_version_sorted_hard(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0-rc.10\n7.63.0-rc.2"
        version = next_rc_version(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 63, 0, rc=11))

    def test_next_rc_version(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0\n7.63.1-rc.1"
        version = next_rc_version(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 63, 1, rc=2))

    def test_next_release_patch_version(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0\n7.63.1-rc.1\n7.63.1"
        version = next_rc_version(ctx, '7.63.x', True)
        print(version)
        self.assertEqual(version, Version(7, 63, 2, rc=1))

    def test_first_rc_version(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0-devel"
        version = next_rc_version(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 63, 0, rc=1))

    def test_no_tag_match(self):
        ctx = MagicMock()
        ctx.run.return_value.stdout = "7.63.0-installer"
        version = next_rc_version(ctx, '7.63.x')
        self.assertEqual(version, Version(7, 64, 0, rc=1))
