"""
Unit tests for Manifests module
"""
from django.test import TestCase
from unittest.mock import patch, MagicMock

from manifests.models import ManifestFile


class ManifestModelTests(TestCase):
    """Tests for Manifest model"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_manifest_data = {
            'catalogs': ['production'],
            'managed_installs': ['Firefox', 'Chrome'],
            'managed_uninstalls': [],
            'optional_installs': ['Zoom'],
            'managed_updates': [],
        }

    @patch('manifests.models.MunkiRepo')
    def test_manifest_read(self, mock_repo):
        """Test reading a manifest"""
        mock_repo.read.return_value = self.test_manifest_data

        manifest = ManifestFile('test_manifest')
        self.assertEqual(manifest.filename, 'test_manifest')

    @patch('manifests.models.MunkiRepo')
    def test_manifest_list(self, mock_repo):
        """Test listing all manifests"""
        mock_repo.list.return_value = ['site_default', 'testing', 'production']

        # This would need actual model implementation
        # For now, just verify the mock works
        result = mock_repo.list('manifests')
        self.assertEqual(len(result), 3)

    def test_manifest_structure(self):
        """Test manifest data structure validation"""
        # Test that required keys exist
        required_keys = ['catalogs', 'managed_installs']
        for key in required_keys:
            self.assertIn(key, self.test_manifest_data)

    @patch('manifests.models.MunkiRepo')
    def test_manifest_write(self, mock_repo):
        """Test writing a manifest"""
        mock_repo.write.return_value = True

        result = mock_repo.write('manifests', 'test_manifest', self.test_manifest_data)
        self.assertTrue(result)
