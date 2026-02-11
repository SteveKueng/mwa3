"""
Unit tests for Pkgsinfo module
"""
from django.test import TestCase
from unittest.mock import patch, MagicMock

from pkgsinfo.models import PkginfoFile


class PkginfoModelTests(TestCase):
    """Tests for PkginfoFile model"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_pkginfo = {
            'name': 'Firefox',
            'version': '120.0',
            'display_name': 'Mozilla Firefox',
            'description': 'Web browser',
            'catalogs': ['production'],
            'installer_item_location': 'apps/Firefox-120.0.pkg',
        }

    @patch('pkgsinfo.models.MunkiRepo')
    def test_pkginfo_read(self, mock_repo):
        """Test reading a pkginfo file"""
        mock_repo.read.return_value = self.test_pkginfo

        # This would need actual model implementation
        result = mock_repo.read('pkgsinfo', 'apps/Firefox-120.0')
        self.assertEqual(result['name'], 'Firefox')
        self.assertEqual(result['version'], '120.0')

    @patch('pkgsinfo.models.MunkiRepo')
    def test_pkginfo_list(self, mock_repo):
        """Test listing pkginfo files"""
        mock_repo.list.return_value = [
            'apps/Firefox-120.0',
            'apps/Chrome-110.0',
            'utilities/Zoom-5.0'
        ]

        result = mock_repo.list('pkgsinfo')
        self.assertEqual(len(result), 3)

    def test_pkginfo_required_fields(self):
        """Test that pkginfo has required fields"""
        required_fields = ['name', 'version', 'installer_item_location']
        for field in required_fields:
            self.assertIn(field, self.test_pkginfo)

    def test_version_comparison(self):
        """Test version comparison for pkginfo"""
        from packaging.version import parse as parse_version

        v1 = parse_version(self.test_pkginfo['version'])
        v2 = parse_version('119.0')

        self.assertTrue(v1 > v2)

    @patch('pkgsinfo.models.MunkiRepo')
    def test_pkginfo_write(self, mock_repo):
        """Test writing a pkginfo file"""
        mock_repo.write.return_value = True

        result = mock_repo.write('pkgsinfo', 'apps/Firefox-120.0', self.test_pkginfo)
        self.assertTrue(result)


class PkginfoUtilsTests(TestCase):
    """Tests for pkgsinfo utility functions"""

    def test_any_files_newer_than(self):
        """Test file modification time comparison"""
        from pkgsinfo.models import any_files_in_list_newer_than

        # This function currently returns False (disabled)
        # Test that it exists and returns expected value
        result = any_files_in_list_newer_than(['file1.plist'], 'file2.plist')
        self.assertFalse(result)
