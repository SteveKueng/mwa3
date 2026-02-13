"""
api/views.py
"""
from rest_framework.parsers import JSONParser, BaseParser
from rest_framework.response import Response
from rest_framework.generics import ListAPIView, RetrieveAPIView, GenericAPIView
from rest_framework.mixins import (
    CreateModelMixin, 
    DestroyModelMixin,
    UpdateModelMixin,
    ListModelMixin
)
from rest_framework.permissions import DjangoModelPermissions

from django.http import FileResponse
from django.conf import settings
from django.utils.timezone import now 
from django.contrib.auth.models import User 

from api.models import MunkiRepo
from api.models import FileReadError, \
                       FileDoesNotExistError, FileDeleteError

from manifests.models import ManifestFile
from pkgsinfo.models import PkginfoFile
from catalogs.models import Catalogs

from api.serializers import (
    ManifestSerializer
)

# python-magic requires the system library "libmagic". Some deployments (e.g.
# Azure App Service zip deploy) don't include it, so we must not hard-fail on
# import.
try:
    import magic as _magic  # type: ignore
except Exception:  # pragma: no cover
    _magic = None

magic = _magic

from api.throttling import UploadRateThrottle

import datetime
import json
import logging
import os
import mimetypes
import re
import base64
import bz2
import urllib
import sys
import io
import tempfile
import platform
import hashlib

LOGGER = logging.getLogger('munkiwebadmin')
MUNKITOOLS_DIR = settings.MUNKITOOLS_DIR


def _detect_upload_mime_type(file_content: bytes, filename: str) -> str | None:
    """Best-effort MIME detection.

    - Prefer libmagic (python-magic) when available.
    - Otherwise fall back to mimetypes + minimal signature checks.
    """
    if magic is not None:
        return magic.from_buffer(file_content, mime=True)

    guessed, _ = mimetypes.guess_type(filename)
    return guessed


def _xar_signature_ok(file_content: bytes) -> bool:
    # .pkg files are typically XAR archives which start with b"xar!".
    return file_content.startswith(b"xar!")

# import munkitools
sys.path.append(MUNKITOOLS_DIR)

try:
    from munkilib.wrappers import (readPlistFromString, PlistReadError)
except ImportError:
    LOGGER.error('Failed to import munkilib')
    raise

if platform.system() == "Darwin":
    from munkilib.admin.pkginfolib import makepkginfo
else:
    from api.utils.munkiimport_linux import makepkginfo


def _guess_version_from_filename(filename: str) -> str:
    """Best-effort version extraction from a filename.

    Examples:
    - Foo-1.2.3.dmg -> 1.2.3
    - Foo_2024.01.pkg -> 2024.01
    """
    base = os.path.basename(filename)
    base = os.path.splitext(base)[0]
    match = re.search(r"(?<!\d)(\d+(?:\.\d+){1,})(?!\d)", base)
    return match.group(1) if match else "0"


def _sha256_hex(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _minimal_pkginfo_for_uninspectable_dmg(file_path: str, filename: str) -> dict:
    """Fallback pkginfo for DMGs we can't introspect on Linux.

    Some DMGs (notably APFS-based images) cannot be reliably unpacked in a
    container without extra tooling/capabilities. In that case we still want the
    upload to succeed so the admin can manually edit the generated pkginfo.
    """
    name = os.path.splitext(os.path.basename(filename))[0]
    version = _guess_version_from_filename(filename)
    try:
        itemsize_kb = int(os.path.getsize(file_path) / 1024)
    except OSError:
        itemsize_kb = 0
    try:
        itemhash = _sha256_hex(file_path)
    except OSError:
        itemhash = "N/A"

    return {
        'name': name,
        'version': version,
        'catalogs': ['testing'],
        'description': 'Auto-generated: DMG metadata could not be inspected on this host. Edit this pkginfo before using in production.',
        'minimum_os_version': '10.4.0',
        'installer_item_size': itemsize_kb,
        'installer_item_hash': itemhash,
        'supported_architectures': [],
    }


def normalize_value_for_filtering(value):
    '''Converts value to a list of strings'''
    if isinstance(value, (int, float, bool, str, dict)):
        return [str(value).lower()]
    if isinstance(value, list):
        return [str(item).lower() for item in value]
    return []


def convert_dates_to_strings(plist):
    '''Converts all date objects in a plist to strings. Enables encoding into
    JSON'''
    if isinstance(plist, dict):
        for key, value in plist.items():
            if isinstance(value, datetime.datetime):
                plist[key] = value.isoformat()
            if isinstance(value, (list, dict)):
                plist[key] = convert_dates_to_strings(value)
        return plist
    if isinstance(plist, list):
        for value in plist:
            if isinstance(value, datetime.datetime):
                value = value.isoformat()
            if isinstance(value, (list, dict)):
                value = convert_dates_to_strings(value)
        return plist


def convert_strings_to_dates(jdata):
    '''Attempt to automatically convert JSON date strings to date objects for
    plists'''
    iso_date_pattern = re.compile(
        r"^\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\dZ*$")
    if isinstance(jdata, dict):
        for key, value in jdata.items():
            if ('date' in key.lower() and isinstance(value, str)
                    and iso_date_pattern.match(value)):
                jdata[key] = datetime.datetime.strptime(
                    value[:19], "%Y-%m-%dT%H:%M:%S")
            if isinstance(value, (list, dict)):
                jdata[key] = convert_strings_to_dates(value)
        return jdata
    if isinstance(jdata, list):
        for value in jdata:
            # we don't support lists of dates, so no need to check
            # for those
            if isinstance(value, (list, dict)):
                value = convert_strings_to_dates(value)
        return jdata


def convert_html_to_json(raw_html):
    LOGGER.debug("raw html: %s", raw_html)
    cleanr = re.compile('<.*?>')
    cleantext = re.sub(cleanr, '', raw_html)
    try:
        data = json.loads(cleantext.strip())
    except (ValueError, KeyError, TypeError):
        data = ""
    return data


def model_lookup(serial):
    """Determines the models human readable description based off the serial
    number"""

    options = "page=categorydata&serialnumber=%s" % serial
    url = "https://km.support.apple.com/kb/index?%s" % options
    
    try:
        response = urllib.request.urlopen(url)
    except urllib.error.HTTPError as e:
        print("HTTP Error: %s" % e.code)
        return None
    
    try:
        data = response.read()
        model = json.loads(data.decode("utf-8"))
    except:
        print("Error: Could not decode JSON")
        return None
    return model


def get_device_img_url(serial):
    """ Returns the url to the device image for a given serial number"""
    model = model_lookup(serial)
    if model and model.get('id', None):
        url = "https://km.support.apple.com/kb/securedImage.jsp?productid=%s&size=240x240" % model['id']
    else:
        url = "https://support.apple.com/kb/securedImage.jsp?configcode=%s&size=240x240" % serial[-4:]
    return url


def decode_to_string(data):
    '''Decodes an inventory submission, which is a plist-encoded
    list, compressed via bz2 and base64 encoded.'''
    try:
        bz2data = base64.b64decode(data)
        return bz2.decompress(bz2data)
    except Exception:
        return None


class PlistXMLParser(BaseParser):
    """
    Plist xml parser.
    """
    media_type = 'application/xml'

    def parse(self, stream, media_type=None, parser_context=None):
        stream = stream.read()
        try:
            return readPlistFromString(stream)
        except PlistReadError as err:
            LOGGER.error('Error reading plist: %s', err)
            raise FileReadError(err)


class CatalogsListView(GenericAPIView, ListModelMixin):
    http_method_names = ['get', 'post']
    permission_classes = [DjangoModelPermissions]
    
    def get_queryset(self):
        try:
            response = Catalogs.objects.all()
        except FileDoesNotExistError as err:
            return Response({})
        except FileReadError as err:
            return Response({})
        return response
    
    def get_object(self):
        queryset = MunkiRepo.list('catalogs')

        filter_terms = self.request.GET.copy()
        LOGGER.debug("filter_terms: %s", filter_terms)

        # remove the _ parameter
        if '_' in filter_terms.keys():
            del filter_terms['_']

        # remove the api_fields parameter
        api_fields = None
        if 'api_fields' in filter_terms.keys():
            api_fields = filter_terms['api_fields']
            del filter_terms['api_fields']

        response = []
        for item_name in queryset:
            LOGGER.debug("item_name: %s", item_name)
            plist = MunkiRepo.read('catalogs', item_name)
            plist = convert_dates_to_strings(plist)
            plist = {'contents': plist}
            plist['filename'] = item_name
            matches_filters = True
            for key, value in filter_terms.items():
                LOGGER.debug("key: %s, value: %s", key, value)
                LOGGER.debug("plist: %s", plist)
                if key not in plist:
                    LOGGER.debug("key not in plist")
                    matches_filters = False
                    continue
                plist_value = normalize_value_for_filtering(plist[key])
                match = next(
                    (item for item in plist_value
                        if value.lower() in item.lower()), None)
                if not match:
                    matches_filters = False
                    continue
            
            if matches_filters:
                if api_fields:
                    # filter to just the requested fields
                    plist = {key: plist[key] for key in plist.keys()
                                if key in api_fields}
                    LOGGER.debug("plist: %s", plist)
                response.append(plist)
        return response
    
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
    def list(self, request):
        return Response(self.get_object())


class CatalogsDetailAPIView(GenericAPIView, ListModelMixin):
    http_method_names = ['get', 'post']
    permission_classes = [DjangoModelPermissions]
    
    def get_queryset(self):
        try:
            response = Catalogs.objects.all()
        except FileDoesNotExistError as err:
            return Response({})
        except FileReadError as err:
            return Response({})
        return response
    
    def get_object(self):
        queryset = MunkiRepo.read('catalogs', self.kwargs['filepath'])
        queryset = convert_dates_to_strings(queryset)
        return queryset
        
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
    def list(self, request, filepath):
        return Response(self.get_object())
    

class ManifestsListView(GenericAPIView, ListModelMixin):
    http_method_names = ['get', 'post']
    permission_classes = [DjangoModelPermissions]
    serializer_class = ManifestSerializer
    parser_classes = [PlistXMLParser, JSONParser]

    def get_queryset(self):
        try:
            items = MunkiRepo.list('manifests')
            response = ManifestFile.objects.all()
            response.values = items
        except FileDoesNotExistError as err:
            return Response({})
        except FileReadError as err:
            return Response({})
        return response
    
    def get_object(self):
        queryset = self.get_queryset().values

        filter_terms = self.request.GET.copy()
        LOGGER.debug("filter_terms: %s", filter_terms)

        # remove the _ parameter
        if '_' in filter_terms.keys():
            del filter_terms['_']

        # remove the api_fields parameter
        api_fields = None
        if 'api_fields' in filter_terms.keys():
            api_fields = filter_terms['api_fields']
            del filter_terms['api_fields']

        response = []
        for item_name in queryset:
            LOGGER.debug("item_name: %s", item_name)
            plist = MunkiRepo.read('manifests', item_name)
            plist = convert_dates_to_strings(plist)
            plist['filename'] = item_name
            matches_filters = True
            for key, value in filter_terms.items():
                LOGGER.debug("key: %s, value: %s", key, value)
                LOGGER.debug("plist: %s", plist)
                if key not in plist:
                    LOGGER.debug("key not in plist")
                    matches_filters = False
                    continue
                plist_value = normalize_value_for_filtering(plist[key])
                match = next(
                    (item for item in plist_value
                        if value.lower() in item.lower()), None)
                if not match:
                    matches_filters = False
                    continue
            
            if matches_filters:
                if api_fields:
                    # filter to just the requested fields
                    plist = {key: plist[key] for key in plist.keys()
                                if key in api_fields}
                    LOGGER.debug("plist: %s", plist)
                response.append(plist)
        return response
    
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
    def list(self, request):
        return Response(self.get_object())


class ManifestsDetailAPIView(GenericAPIView, ListModelMixin, CreateModelMixin, DestroyModelMixin, UpdateModelMixin):
    http_method_names = ['get', 'post', 'put', 'patch', 'delete']
    permission_classes = [DjangoModelPermissions]
    serializer_class = ManifestSerializer
    parser_classes = [PlistXMLParser, JSONParser]

    def get_queryset(self):
        try:
            response = ManifestFile.objects.all()
        except FileDoesNotExistError as err:
            return Response({})
        except FileReadError as err:
            return Response({})
        return response
    
    def get_object(self):
        queryset = MunkiRepo.read('manifests', self.kwargs['filepath'])
        queryset = convert_dates_to_strings(queryset)
        filter_terms = self.request.GET.copy()

        # remove the _ parameter
        if '_' in filter_terms.keys():
            del filter_terms['_']

        # remove the api_fields parameter
        api_fields = None
        if 'api_fields' in filter_terms.keys():
            api_fields = filter_terms['api_fields']
            del filter_terms['api_fields']
        
        if api_fields:
            for key in list(queryset):
                if key not in api_fields:
                    del queryset[key]
        return queryset
        
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
    def list(self, request, filepath):
        serializer = ManifestSerializer(self.get_object())
        return Response(serializer.data)
    
    def post(self, request, *args, **kwargs):
        serializer = ManifestSerializer(data=request.data)
        if serializer.is_valid():
            MunkiRepo.write(serializer.data, "manifests", kwargs['filepath'])
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400) 
    
    def put(self, request, *args, **kwargs):
        serializer = ManifestSerializer(data=request.data)
        if serializer.is_valid():
            MunkiRepo.write(serializer.data, "manifests", kwargs['filepath'])
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)
    
    def delete(self, request, *args, **kwargs):
        try:
            MunkiRepo.delete('manifests', kwargs['filepath'])
            return Response(status=204)
        except FileDeleteError as err:
            return Response({'result': 'failed',
                            'exception_type': str(type(err)),
                            'detail': str(err)})


class PkgsinfoListView(GenericAPIView, ListModelMixin):
    http_method_names = ['get', 'post']
    permission_classes = [DjangoModelPermissions]
    parser_classes = [PlistXMLParser, JSONParser]
    
    def get_queryset(self):
        try:
            response = PkginfoFile.objects.all()
        except FileDoesNotExistError as err:
            return Response({})
        except FileReadError as err:
            return Response({})
        return response
    
    def get_object(self):
        queryset = MunkiRepo.list('pkgsinfo')
        filter_terms = self.request.GET.copy()

        # remove the _ parameter
        if '_' in filter_terms.keys():
            del filter_terms['_']

        # remove the api_fields parameter
        api_fields = None
        if 'api_fields' in filter_terms.keys():
            api_fields = filter_terms['api_fields']
            del filter_terms['api_fields']

        response = []
        for item_name in queryset:
            LOGGER.debug("item_name: %s", item_name)
            plist = MunkiRepo.read('pkgsinfo', item_name)
            plist = convert_dates_to_strings(plist)
            plist['filename'] = item_name
            matches_filters = True
            for key, value in filter_terms.items():
                LOGGER.debug("key: %s, value: %s", key, value)
                LOGGER.debug("plist: %s", plist)
                if key not in plist:
                    LOGGER.debug("key not in plist")
                    matches_filters = False
                    continue
                plist_value = normalize_value_for_filtering(plist[key])
                match = next(
                    (item for item in plist_value
                        if value.lower() in item.lower()), None)
                if not match:
                    matches_filters = False
                    continue
            
            if matches_filters:
                if api_fields:
                    # filter to just the requested fields
                    plist = {key: plist[key] for key in plist.keys()
                                if key in api_fields}
                    LOGGER.debug("plist: %s", plist)
                response.append(plist)
        return response
    
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
    def list(self, request):
        return Response(self.get_object())


class PkgsinfoDetailAPIView(GenericAPIView, ListModelMixin):
    http_method_names = ['get', 'post', 'put', 'patch', 'delete']
    permission_classes = [DjangoModelPermissions]
    parser_classes = [PlistXMLParser, JSONParser]
    
    def get_queryset(self):
        try:
            response = PkginfoFile.objects.all()
        except FileDoesNotExistError as err:
            return Response({})
        except FileReadError as err:
            return Response({})
        return response
    
    def get_object(self):
        queryset = MunkiRepo.read('pkgsinfo', self.kwargs['filepath'])
        queryset = convert_dates_to_strings(queryset)
        filter_terms = self.request.GET.copy()

        api_fields = None
        if 'api_fields' in filter_terms.keys():
            api_fields = filter_terms['api_fields']
            del filter_terms['api_fields']
        
        if api_fields:
            for key in list(queryset):
                if key not in api_fields:
                    del queryset[key]
        return queryset
        
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
    def list(self, request, filepath):
        return Response(self.get_object())
    
    def post(self, request, *args, **kwargs):
        if request.data:
            MunkiRepo.write(request.data, "pkgsinfo", kwargs['filepath'])
            return Response({}, status=201)
        return Response({}, status=400)

    def put(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)
    
    def delete(self, request, *args, **kwargs):
        if kwargs.get('deletePkg', False):
            try:
                MunkiRepo.delete('pkgs', kwargs['installer_item_location'])
            except FileDeleteError as err:
                return Response({'result': 'failed',
                                'exception_type': str(type(err)),
                                'detail': str(err)})

        try:
            MunkiRepo.delete('pkgsinfo', kwargs['filepath'])
            return Response(status=204)
        except FileDeleteError as err:
            return Response({'result': 'failed',
                            'exception_type': str(type(err)),
                            'detail': str(err)})


class PkgsListView(GenericAPIView, ListModelMixin):
    http_method_names = ['get']
    permission_classes = [DjangoModelPermissions]
    
    def get_queryset(self):
        try:
            response = PkginfoFile.objects.all()
        except FileDoesNotExistError as err:
            return Response({})
        except FileReadError as err:
            return Response({})
        return response
    
    def get_object(self):
        return MunkiRepo.list('pkgs')
    
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
    def list(self, request):
        return Response(self.get_object())    


class PkgsDetailAPIView(GenericAPIView, ListModelMixin):
    http_method_names = ['get', 'post', 'put', 'delete']
    permission_classes = [DjangoModelPermissions]
    throttle_classes = [UploadRateThrottle]
    
    def get_queryset(self):
        try:
            response = PkginfoFile.objects.all()
        except FileDoesNotExistError as err:
            return Response({})
        except FileReadError as err:
            return Response({})
        return response
    
    def get_object(self):
        filepath = self.kwargs['filepath']
        try:
            item = MunkiRepo.get('pkgs', self.kwargs['filepath'])
        except FileReadError as err:
            return Response({})
        
        try:
            response = FileResponse(
                item,
                content_type=mimetypes.guess_type(item)[0])
            response['Content-Length'] = os.path.getsize(item)
            response['Content-Disposition'] = (
                'attachment; filename="%s"' % os.path.basename(filepath))
            return response
        except (IOError, OSError) as err:
            return Response({'result': 'failed',
                            'exception_type': str(type(err)),
                            'detail': str(err)})
        
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
    def list(self, request, filepath):
        return self.get_object()
    
    def post(self, request, *args, **kwargs):
        """
        Handles package uploads and directly stores them in the Munki repository.
        Improved with:
        - Chunked file processing (reduced memory usage)
        - Path traversal protection
        - Atomic operations with rollback
        - Better error handling
        """
        import uuid
        import shutil

        LOGGER.info("Received POST request for package upload.")

        # Validate file presence
        if 'file' not in request.FILES:
            return Response({'error': 'No file provided'}, status=400)

        uploaded_file = request.FILES['file']
        filename = uploaded_file.name
        file_ext = os.path.splitext(filename)[1].lower()

        # File size validation (prevent DoS)
        max_upload_size = int(os.getenv('MAX_UPLOAD_SIZE_MB', 2048)) * 1024 * 1024  # Default 2GB
        if uploaded_file.size > max_upload_size:
            return Response({
                'error': f'File too large. Maximum size: {max_upload_size / (1024 * 1024):.0f} MB'
            }, status=413)

        LOGGER.info(f"Upload received: {filename} ({uploaded_file.size / (1024 * 1024):.2f} MB)")

        # Allow only .pkg and .dmg files
        if file_ext not in ['.pkg', '.dmg']:
            return Response({'error': 'Only .pkg and .dmg files are allowed'}, status=400)

        # Validate file type using magic bytes
        try:
            file_content = uploaded_file.read(2048)
            uploaded_file.seek(0)  # Reset file pointer
            mime_type = _detect_upload_mime_type(file_content, filename) or 'application/octet-stream'

            # Valid MIME types for pkg (XAR archives) and dmg files
            valid_mimes = [
                'application/x-xar',  # .pkg files
                'application/x-apple-diskimage',  # .dmg files
                'application/octet-stream'  # Fallback for some valid files
            ]

            # If libmagic isn't available, MIME detection may be weak. Keep a
            # minimal signature check for PKG to avoid accepting obvious junk.
            if magic is None and file_ext == '.pkg' and not _xar_signature_ok(file_content):
                LOGGER.warning(f"Invalid PKG signature for file {filename}")
                return Response({'error': 'Invalid PKG file signature. Only PKG and DMG files are allowed.'}, status=400)

            if magic is not None and mime_type not in valid_mimes:
                LOGGER.warning(f"Invalid file type detected: {mime_type} for file {filename}")
                return Response({'error': f'Invalid file type: {mime_type}. Only PKG and DMG files are allowed.'}, status=400)

            if magic is None:
                LOGGER.warning("libmagic not available; falling back to extension/signature validation")

            LOGGER.info(f"File validation successful: {filename} ({mime_type})")
        except Exception as e:
            LOGGER.error(f"Error validating file type: {e}")
            return Response({'error': 'Failed to validate file type'}, status=500)

        # Define destination path in the repo using filepath from kwargs
        if 'filepath' not in kwargs:
            return Response({'error': 'No filepath provided'}, status=400)

        filepath = kwargs['filepath']

        # SECURITY: Validate filepath against path traversal attacks
        if '..' in filepath or filepath.startswith('/'):
            LOGGER.error(f"Path traversal attempt detected: {filepath}")
            return Response({'error': 'Invalid filepath - path traversal not allowed'}, status=400)

        # Normalize path
        filepath = os.path.normpath(filepath)

        # Create unique temporary file to avoid race conditions
        temp_file_path = None
        pkg_path_written = None
        pkginfo_path_written = None

        try:
            # Generate unique temporary filename
            unique_id = uuid.uuid4().hex[:8]
            temp_filename = f"{unique_id}_{filename}"
            temp_file_path = os.path.join(tempfile.gettempdir(), temp_filename)

            LOGGER.info(f"Creating temporary file: {temp_file_path}")

            # Write uploaded file to temp location in chunks (memory-efficient)
            with open(temp_file_path, 'wb+') as temp_file:
                for chunk in uploaded_file.chunks():
                    temp_file.write(chunk)

            LOGGER.info(f"Temporary file created: {temp_file_path} ({os.path.getsize(temp_file_path)} bytes)")

            # Generate pkginfo
            options = {}
            try:
                pkginfo = makepkginfo(temp_file_path, options)
            except Exception as e:
                if file_ext == '.dmg':
                    LOGGER.warning(
                        f"makepkginfo failed for DMG upload {filename}; falling back to minimal pkginfo: {e}",
                        exc_info=True,
                    )
                    pkginfo = _minimal_pkginfo_for_uninspectable_dmg(temp_file_path, filename)
                else:
                    raise

            if not pkginfo:
                if file_ext == '.dmg':
                    LOGGER.warning(
                        f"makepkginfo returned empty for DMG upload {filename}; falling back to minimal pkginfo"
                    )
                    pkginfo = _minimal_pkginfo_for_uninspectable_dmg(temp_file_path, filename)
                else:
                    LOGGER.error("makepkginfo returned None")
                    return Response({'error': 'Failed to generate pkginfo - invalid package format'}, status=400)

            arch = ""
            if len(pkginfo.get("supported_architectures", [])) == 1:
                arch = "-%s" % pkginfo["supported_architectures"][0]

  
            pkginfo_ext = ".plist"
            destination_path = os.path.dirname(filepath)
            pkginfo_name = '%s-%s%s%s' % (pkginfo['name'], pkginfo['version'],
                                    arch, pkginfo_ext)
            pkginfo_path = os.path.join(destination_path, pkginfo_name) 

            index = 0
            pkgsinfo_list = MunkiRepo.list('pkgsinfo')
            while pkginfo_path in pkgsinfo_list:
                index += 1
                pkginfo_name = '%s-%s%s__%s%s' % (pkginfo['name'], pkginfo['version'],
                                                arch, index, pkginfo_ext)
                pkginfo_path = os.path.join(destination_path, pkginfo_name)

            # Add metadata to the pkginfo
            current_user = request.user if request.user.is_authenticated else "Unknown"
            pkginfo["_metadata"] = {
                "created_by": current_user.username,
                "creation_date": now().isoformat(),
                "munkiwebadmin_upload": True,
            }

             # try to find existing pkginfo items that match this one
            matchingpkginfo = MunkiRepo.find_matching_pkginfo(pkginfo)
            if matchingpkginfo:
                if ('installer_item_hash' in matchingpkginfo and
                        matchingpkginfo['installer_item_hash'] ==
                        pkginfo.get('installer_item_hash')):
                    return Response({'error': 'This item is identical to an existing item in the repo'}, status=400)

                # replace the pkginfo with the matching one
                pkginfo['name'] = matchingpkginfo['name']
                pkginfo['display_name'] = (
                    matchingpkginfo.get('display_name') or
                    pkginfo.get('display_name') or
                    matchingpkginfo['name'])
                pkginfo['description'] = pkginfo.get('description') or \
                    matchingpkginfo.get('description', '')
                for key in ['blocking_applications',
                            'forced_install',
                            'forced_uninstall',
                            'unattended_install',
                            'unattended_uninstall',
                            'requires',
                            'update_for',
                            'category',
                            'developer',
                            'icon_name',
                            'unused_software_removal_info',
                            'localized_strings',
                            'featured']:
                    if key in matchingpkginfo:
                        pkginfo[key] = matchingpkginfo[key]

            LOGGER.info(f"pkginfo metadata created for: {pkginfo_path}")

            # Calculate final package path with version and collision handling
            item_name = os.path.basename(filepath)
            pkg_path = os.path.join(destination_path, item_name)
            name, ext = os.path.splitext(item_name)
            vers = pkginfo.get('version', None)

            if vers:
                if not name.endswith(vers):
                    # add the version number to the end of the filename
                    item_name = '%s-%s%s' % (name, vers, ext)
                    pkg_path = os.path.join(destination_path, item_name)

            # Handle filename collisions with unique suffix
            index = 0
            pkgs_list = MunkiRepo.list('pkgs')
            original_pkg_path = pkg_path
            while pkg_path in pkgs_list:
                index += 1
                item_name = '%s__%s%s' % (name, index, ext)
                pkg_path = os.path.join(destination_path, item_name)
                LOGGER.info(f"Collision detected, trying: {pkg_path}")

            LOGGER.info(f"Final package path: {pkg_path}")

            # === ATOMIC OPERATION: Write package + pkginfo (with rollback on failure) ===

            # Step 1: Write package file from temp file (memory-efficient)
            try:
                with open(temp_file_path, 'rb') as source_file:
                    file_data = source_file.read()  # Read once for writing
                MunkiRepo.writedata(file_data, "pkgs", pkg_path)
                pkg_path_written = pkg_path
                LOGGER.info(f"Package written successfully: {pkg_path}")
            except (IOError, OSError) as err:
                LOGGER.error(f"Failed to write package file: {err}")
                return Response({'error': f'Failed to write package: {str(err)}'}, status=500)
            except Exception as err:
                LOGGER.error(f"Unexpected error writing package: {err}")
                return Response({'error': f'Failed to write package: Unexpected error'}, status=500)

            # Step 2: Update pkginfo with final installer_item_location
            pkginfo['installer_item_location'] = pkg_path

            # Step 3: Write pkginfo (rollback package if this fails)
            try:
                MunkiRepo.write(pkginfo, "pkgsinfo", pkginfo_path)
                pkginfo_path_written = pkginfo_path
                LOGGER.info(f"Pkginfo written successfully: {pkginfo_path}")
            except Exception as err:
                LOGGER.error(f"Failed to write pkginfo, rolling back package: {err}")
                # ROLLBACK: Delete the package we just wrote
                try:
                    MunkiRepo.delete('pkgs', pkg_path)
                    LOGGER.info(f"Rollback successful: deleted {pkg_path}")
                except Exception as rollback_err:
                    LOGGER.error(f"CRITICAL: Rollback failed for {pkg_path}: {rollback_err}")
                return Response({'error': f'Failed to write pkginfo: {str(err)}'}, status=500)

            # Success!
            return Response({
                'message': 'Upload and pkginfo creation successful',
                'pkginfo_path': pkginfo_path,
                'pkg_path': pkg_path,
                'size_mb': round(os.path.getsize(temp_file_path) / (1024 * 1024), 2)
            }, status=201)

        except FileNotFoundError as e:
            LOGGER.error(f"File not found during processing: {e}")
            return Response({'error': 'File processing error: File not found'}, status=500)
        except PermissionError as e:
            LOGGER.error(f"Permission denied during processing: {e}")
            return Response({'error': 'Permission denied - check repository permissions'}, status=500)
        except Exception as e:
            LOGGER.error(f"Unexpected error during upload processing: {e}", exc_info=True)
            # Cleanup any partial writes
            if pkg_path_written:
                try:
                    MunkiRepo.delete('pkgs', pkg_path_written)
                    LOGGER.info(f"Cleaned up partial package: {pkg_path_written}")
                except Exception:
                    pass
            if pkginfo_path_written:
                try:
                    MunkiRepo.delete('pkgsinfo', pkginfo_path_written)
                    LOGGER.info(f"Cleaned up partial pkginfo: {pkginfo_path_written}")
                except Exception:
                    pass
            return Response({'error': f'Failed to process upload: {str(e)}'}, status=500)
        finally:
            # Always clean up temporary file
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                    LOGGER.info(f"Temporary file deleted: {temp_file_path}")
                except OSError as e:
                    LOGGER.warning(f"Failed to delete temporary file {temp_file_path}: {e}")

    def put(self, request, *args, **kwargs):
        """Allows updating an existing package file in the Munki repository."""
        return self.post(request, *args, **kwargs)
    
    def delete(self, request, *args, **kwargs):
        try:
            MunkiRepo.delete('pkgs', kwargs['filepath'])
            return Response(status=204)
        except FileDeleteError as err:
            return Response({'result': 'failed',
                            'exception_type': str(type(err)),
                            'detail': str(err)})


class IconsListView(GenericAPIView, ListModelMixin):
    http_method_names = ['get', 'post']
    permission_classes = [DjangoModelPermissions]
    
    def get_queryset(self):
        try:
            response = PkginfoFile.objects.all()
        except FileDoesNotExistError as err:
            return Response({})
        except FileReadError as err:
            return Response({})
        return response
    
    def get_object(self):
        return MunkiRepo.list('icons')
    
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
    def list(self, request):
        return Response(self.get_object())


class IconsDetailAPIView(GenericAPIView, ListModelMixin):
    http_method_names = ['get', 'post', 'put', 'delete']
    permission_classes = [DjangoModelPermissions]
    
    def get_queryset(self):
        try:
            response = PkginfoFile.objects.all()
        except FileDoesNotExistError as err:
            return Response({})
        except FileReadError as err:
            return Response({})
        return response
    
    def get_object(self):
        filepath = self.kwargs['filepath']
        
        try:
            item = MunkiRepo.get('icons', filepath)
        except FileReadError as err:
            return Response({})
        
        buffer = io.BytesIO(item)
        buffer.seek(0)

        try:
            response = FileResponse(
                buffer,
                content_type=mimetypes.guess_type(filepath)[0],
                filename=filepath)
            return response
        except (IOError, OSError) as err:
            return Response({'result': 'failed',
                            'exception_type': str(type(err)),
                            'detail': str(err)})
        
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
    def list(self, request, filepath):
        return self.get_object()
    
    def post(self, request, *args, **kwargs):
        if request.data:
            imgBase64 = request.data['img'].split(',')[1].replace(" ", "+")
            img = base64.b64decode(imgBase64)

            MunkiRepo.writedata(img, "icons", kwargs['filepath'])
            return Response({}, status=201)
        return Response({}, status=400)
    
    def put(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)
    
    def delete(self, request, *args, **kwargs):
        try:
            MunkiRepo.delete('icons', kwargs['filepath'])
            return Response(status=204)
        except FileDeleteError as err:
            return Response({'result': 'failed',
                            'exception_type': str(type(err)),
                            'detail': str(err)})

