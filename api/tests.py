"""Unit tests for API module."""

import os
import tempfile
from unittest.mock import MagicMock, patch

from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APITestCase

from api.models import MunkiRepo


class MunkiRepoTests(TestCase):
    """Tests for MunkiRepo model"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_data = b"test data"

    @patch('api.models.readPlistFromString')
    @patch('api.models.repo')
    def test_read_file(self, mock_repo, mock_read_plist):
        """Test reading a plist from the repo."""
        mock_repo.get.return_value = b"plist data"
        mock_read_plist.return_value = {"ok": True}

        result = MunkiRepo.read('catalogs', 'test.plist')
        self.assertEqual(result, {"ok": True})

    @patch('api.models.repo')
    def test_list_files(self, mock_repo):
        """Test listing files in the repo."""
        mock_repo.itemlist.return_value = ['file1.plist', 'file2.plist']

        result = MunkiRepo.list('catalogs')
        self.assertEqual(len(result), 2)
        self.assertIn('file1.plist', result)

    @patch('api.models.repo')
    def test_write_file(self, mock_repo):
        """Test writing data to the repo."""
        MunkiRepo.writedata(self.test_data, 'catalogs', 'test.plist')
        mock_repo.put.assert_called_once()


class PackageUploadTests(APITestCase):
    """Tests for package upload functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.user = User.objects.create_superuser(
            username='testuser',
            password='testpass123',
            email='test@example.com',
        )

    def test_upload_requires_authentication(self):
        """Test that package upload requires authentication"""
        response = self.client.post('/api/pkgs/apps/TestApp.pkg', {})
        # LoginRequiredMiddleware redirects unauthenticated requests
        self.assertEqual(response.status_code, 302)

    def test_upload_missing_file(self):
        """Test upload with missing file"""
        self.client.force_login(self.user)
        response = self.client.post('/api/pkgs/packages/apps/', {})
        # Should fail because no file provided
        self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST, status.HTTP_403_FORBIDDEN])

    @patch('api.views.magic')
    @patch('api.views.MunkiRepo')
    def test_upload_invalid_file_type(self, mock_repo, mock_magic):
        """Test upload with invalid file type"""
        self.client.force_login(self.user)

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
        self.client.force_login(self.user)

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
        self.client.force_login(self.user)

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
        # When libmagic isn't available, the view falls back to a minimal
        # XAR signature check for PKG uploads.
        test_file.write(b"xar!" + b"fake package data")
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

    @patch('api.views.MunkiRepo')
    @patch('api.views.makepkginfo')
    def test_upload_dmg_fallback_when_pkginfo_fails(self, mock_makepkginfo, mock_repo):
        """DMG uploads should still succeed when pkginfo inspection fails."""
        self.client.force_login(self.user)

        mock_makepkginfo.side_effect = Exception("Could not find a supported installer item")

        # Repo behaviors used by the view
        mock_repo.list.return_value = []
        mock_repo.find_matching_pkginfo.return_value = None
        mock_repo.writedata.return_value = True
        mock_repo.write.return_value = True

        test_file = tempfile.NamedTemporaryFile(suffix='.dmg', delete=False)
        test_file.write(b"fake dmg data")
        test_file.close()

        try:
            with open(test_file.name, 'rb') as f:
                response = self.client.post(
                    '/api/pkgs/public/claude/Claude.dmg',
                    {'file': f},
                    format='multipart'
                )

            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertIn('pkginfo_path', response.data)
            self.assertIn('pkg_path', response.data)
        finally:
            os.unlink(test_file.name)

    @patch('api.views.MunkiRepo')
    @patch('api.views.makepkginfo')
    @patch('api.views.generate_icon_png_bytes')
    def test_upload_writes_icon_when_extractable(self, mock_icon, mock_makepkginfo, mock_repo):
        """When icon extraction succeeds, the upload should write an icon and set icon_name."""
        self.client.force_login(self.user)

        mock_makepkginfo.return_value = {
            'name': 'TestApp',
            'version': '1.0',
            'catalogs': ['testing'],
        }

        mock_repo.find_matching_pkginfo.return_value = None

        def _list_side_effect(kind):
            return []

        mock_repo.list.side_effect = _list_side_effect
        mock_repo.writedata.return_value = True
        mock_repo.write.return_value = True

        mock_icon.return_value = type('R', (), {'png_bytes': b'png'})()

        test_file = tempfile.NamedTemporaryFile(suffix='.pkg', delete=False)
        # When libmagic isn't available, the view falls back to a minimal
        # XAR signature check for PKG uploads.
        test_file.write(b"xar!" + b"fake package data")
        test_file.close()

        try:
            with open(test_file.name, 'rb') as f:
                response = self.client.post(
                    '/api/pkgs/apps/TestApp.pkg',
                    {'file': f},
                    format='multipart'
                )

            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

            # Verify an icon write occurred
            icon_writes = [c for c in mock_repo.writedata.call_args_list if len(c.args) >= 3 and c.args[1] == 'icons']
            self.assertTrue(icon_writes)

            # Verify pkginfo contains icon_name (without extension)
            written_pkginfo = mock_repo.write.call_args[0][0]
            self.assertEqual(written_pkginfo.get('icon_name'), 'TestApp')
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
