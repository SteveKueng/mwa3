"""
Unit tests for Catalogs module
"""
from django.test import TestCase
from unittest.mock import patch, MagicMock

from catalogs.models import Catalog, Catalogs


class CatalogModelTests(TestCase):
    """Tests for Catalog model"""

    @patch('catalogs.models.MunkiRepo')
    def test_catalog_read(self, mock_repo):
        """Test reading a catalog"""
        mock_repo.read.return_value = {
            'name': 'test_catalog',
            'items': []
        }

        catalog = Catalog('test_catalog')
        self.assertEqual(catalog.filename, 'test_catalog')

    @patch('catalogs.models.MunkiRepo')
    def test_catalogs_list(self, mock_repo):
        """Test listing all catalogs"""
        mock_repo.list.return_value = ['production', 'testing', 'development']

        catalogs = list(Catalogs.objects.all())
        self.assertEqual(len(catalogs), 3)

    def test_catalog_validation(self):
        """Test catalog validation"""
        # Test that catalog names are valid
        valid_names = ['production', 'testing', 'development', 'all']
        for name in valid_names:
            catalog = Catalog(name)
            self.assertIsNotNone(catalog.filename)
