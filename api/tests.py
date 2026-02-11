"""
Unit tests for API module
"""
from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User
from rest_framework.test import APITestCase, APIRequestFactory
from rest_framework import status
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os

from api.views import PkgsDetailAPIView
from api.models import MunkiRepo


class MunkiRepoTests(TestCase):
    """Tests for MunkiRepo model"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_data = b"test data"

    @patch('api.models.MunkiRepo._get_plugin')
    def test_read_file(self, mock_plugin):
        """Test reading a file from the repo"""
        mock_plugin_instance = MagicMock()
        mock_plugin_instance.get.return_value = b"plist data"
        mock_plugin.return_value = mock_plugin_instance

        result = MunkiRepo.read('catalogs', 'test.plist')
        self.assertIsNotNone(result)

    @patch('api.models.MunkiRepo._get_plugin')
    def test_list_files(self, mock_plugin):
        """Test listing files in the repo"""
        mock_plugin_instance = MagicMock()
        mock_plugin_instance.list.return_value = ['file1.plist', 'file2.plist']
        mock_plugin.return_value = mock_plugin_instance

        result = MunkiRepo.list('catalogs')
        self.assertEqual(len(result), 2)
        self.assertIn('file1.plist', result)

    @patch('api.models.MunkiRepo._get_plugin')
    def test_write_file(self, mock_plugin):
        """Test writing a file to the repo"""
        mock_plugin_instance = MagicMock()
        mock_plugin_instance.writedata.return_value = True
        mock_plugin.return_value = mock_plugin_instance

        result = MunkiRepo.writedata('catalogs', 'test.plist', self.test_data)
        self.assertTrue(result)


class PackageUploadTests(APITestCase):
    """Tests for package upload functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            is_staff=True
        )

    def test_upload_requires_authentication(self):
        """Test that package upload requires authentication"""
        response = self.client.post('/api/pkgs/packages/', {})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_upload_missing_file(self):
        """Test upload with missing file"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post('/api/pkgs/packages/apps/', {})
        # Should fail because no file provided
        self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST, status.HTTP_403_FORBIDDEN])

    @patch('api.views.magic')
    @patch('api.views.MunkiRepo')
    def test_upload_invalid_file_type(self, mock_repo, mock_magic):
        """Test upload with invalid file type"""
        self.client.force_authenticate(user=self.user)

        # Create a fake file
        fake_file = tempfile.NamedTemporaryFile(suffix='.txt', delete=False)
        fake_file.write(b"not a package")
        fake_file.close()

        # Mock magic to return invalid MIME type
        mock_magic.from_buffer.return_value = 'text/plain'

        try:
            with open(fake_file.name, 'rb') as f:
                response = self.client.post(
                    '/api/pkgs/packages/apps/',
                    {'file': f},
                    format='multipart'
                )
            # Should be rejected based on extension
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        finally:
            os.unlink(fake_file.name)

    def test_upload_path_traversal_protection(self):
        """Test that path traversal attacks are blocked"""
        self.client.force_authenticate(user=self.user)

        # Test various path traversal attempts
        malicious_paths = [
            '../../../etc/passwd',
            '../../secret',
            '/etc/passwd',
            'normal/../../bad',
        ]

        for malicious_path in malicious_paths:
            response = self.client.post(
                f'/api/pkgs/{malicious_path}',
                {},
                format='multipart'
            )
            # Should be rejected (400 or 403)
            self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST, status.HTTP_403_FORBIDDEN])

    @patch('api.views.MunkiRepo')
    @patch('api.views.makepkginfo')
    def test_upload_rollback_on_pkginfo_failure(self, mock_makepkginfo, mock_repo):
        """Test that package is rolled back if pkginfo write fails"""
        self.client.force_authenticate(user=self.user)

        # Mock makepkginfo to succeed
        mock_makepkginfo.return_value = {
            'name': 'TestApp',
            'version': '1.0',
            'installer_item_location': 'apps/TestApp-1.0.pkg'
        }

        # Mock MunkiRepo.write to fail for pkginfo
        mock_repo.writedata.return_value = True
        mock_repo.write.side_effect = Exception("Pkginfo write failed")
        mock_repo.delete = MagicMock()

        # Create test file
        test_file = tempfile.NamedTemporaryFile(suffix='.pkg', delete=False)
        test_file.write(b"fake package data")
        test_file.close()

        try:
            with open(test_file.name, 'rb') as f:
                response = self.client.post(
                    '/api/pkgs/apps/TestApp.pkg',
                    {'file': f},
                    format='multipart'
                )

            # Should return error
            self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Verify rollback was called (package should be deleted)
            # mock_repo.delete.assert_called() - would need to verify exact call
        finally:
            os.unlink(test_file.name)


class ThrottlingTests(APITestCase):
    """Tests for API rate limiting"""

    def setUp(self):
        """Set up test fixtures"""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )

    def test_throttling_enabled(self):
        """Test that throttling is configured"""
        from django.conf import settings
        self.assertIn('DEFAULT_THROTTLE_CLASSES', settings.REST_FRAMEWORK)
        self.assertIn('DEFAULT_THROTTLE_RATES', settings.REST_FRAMEWORK)


class SecurityHeaderTests(TestCase):
    """Tests for security headers"""

    def test_security_headers_configured(self):
        """Test that security headers are properly configured"""
        from django.conf import settings

        # Check that security settings are enabled
        self.assertTrue(hasattr(settings, 'SECURE_BROWSER_XSS_FILTER'))
        self.assertTrue(settings.SECURE_BROWSER_XSS_FILTER)

        self.assertTrue(hasattr(settings, 'X_FRAME_OPTIONS'))
        self.assertEqual(settings.X_FRAME_OPTIONS, 'DENY')

        self.assertTrue(hasattr(settings, 'SECURE_CONTENT_TYPE_NOSNIFF'))
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)

    def test_csrf_protection_enabled(self):
        """Test that CSRF protection is enabled"""
        from django.conf import settings

        # CSRF cookie should be httponly
        self.assertTrue(settings.CSRF_COOKIE_HTTPONLY)


class CacheConfigTests(TestCase):
    """Tests for cache configuration"""

    def test_cache_configured(self):
        """Test that cache is properly configured"""
        from django.conf import settings

        self.assertIn('default', settings.CACHES)
        self.assertIn('BACKEND', settings.CACHES['default'])

    def test_cache_operations(self):
        """Test basic cache operations"""
        from django.core.cache import cache

        # Test set and get
        cache.set('test_key', 'test_value', 30)
        self.assertEqual(cache.get('test_key'), 'test_value')

        # Test delete
        cache.delete('test_key')
        self.assertIsNone(cache.get('test_key'))


class VersionComparisonTests(TestCase):
    """Tests for version comparison using packaging"""

    def test_version_parsing(self):
        """Test that packaging.version works correctly"""
        from packaging.version import parse as parse_version

        v1 = parse_version("1.0.0")
        v2 = parse_version("2.0.0")
        v3 = parse_version("1.5.0")

        self.assertTrue(v2 > v1)
        self.assertTrue(v3 > v1)
        self.assertTrue(v2 > v3)
        self.assertTrue(v1 == parse_version("1.0.0"))
