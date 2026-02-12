"""
pkgsinfo/views.py
"""

from django.http import HttpResponse, Http404
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.http import JsonResponse

from pkgsinfo.models import Pkginfo, PKGSINFO_STATUS_TAG
from process.models import Process
from api.models import MunkiRepo, \
                       FileError, FileDoesNotExistError

import json
import logging
import os
import plistlib
import urllib
import base64

STATIC_URL = settings.STATIC_URL
LOGGER = logging.getLogger('munkiwebadmin')

# load settings
try:
    SHOW_ICONS = settings.SHOW_ICONS
except:
    SHOW_ICONS = False


def get_icon_url(pkginfo_plist):
    '''Attempt to build an icon url for the pkginfo'''
    icon_known_exts = ['.bmp', '.gif', '.icns', '.jpg', '.jpeg', '.png',
                        '.psd', '.tga', '.tif', '.tiff', '.yuv']
    icon_name = pkginfo_plist.get('icon_name') or pkginfo_plist['name']
    if not os.path.splitext(icon_name)[1] in icon_known_exts:
        icon_name += '.png'
    return "/api/icons/" + urllib.parse.quote(icon_name.encode('UTF-8'))


def status(request):
    '''Get and return a status message for the process generating
    the pkgsinfo list'''
    LOGGER.debug('got status request for pkgsinfo_list_process')
    status_response = {}
    processes = Process.objects.filter(name=PKGSINFO_STATUS_TAG)
    if processes:
        # display status from one of the active processes
        # (hopefully there is only one!)
        process = processes[0]
        status_response['statustext'] = process.statustext
    else:
        status_response['statustext'] = 'Processing'
    return HttpResponse(json.dumps(status_response),
                        content_type='application/json')

@login_required
def getjson(request):
    '''Return pkgsinfo as json data -- used by the DataTable that
    displays the list of pkginfo items. Perhaps could be moved into the
    index methods'''
    LOGGER.debug("Got json request for pkgsinfo")
    try:
        pkginfo_list = Pkginfo.data()
    except Exception as err:
        LOGGER.exception('Failed to build pkgsinfo JSON: %s', err)
        return JsonResponse({'error': 'Failed to load pkgsinfo list'}, status=500)

    return JsonResponse(pkginfo_list, safe=False)

@login_required
def index(request):
    '''Index methods: GET and POST'''
    if request.method == "GET":
        LOGGER.debug("Got index request for pkgsinfo")
        context = {'page': 'pkgsinfo',
                   'search': request.GET.get('search', ''),
                   'catalog': request.GET.get('catalog', 'all')}
        return render(request, 'pkgsinfo/pkgsinfo.html', context=context)
    if request.method == "DELETE":
        LOGGER.info("Got mass delete request for pkginfos")
        if not request.user.has_perm('pkgsinfo.delete_pkginfofile'):
            return HttpResponse(
                json.dumps({
                    'result': 'failed',
                    'exception_type': 'PkginfoDeletePermissionDenied',
                    'detail': "Missing needed permissions"}),
                content_type='application/json', status=403)
        json_data = json.loads(request.body)
        pkginfo_list = json_data.get('pkginfo_list', [])
        try:
            Pkginfo.mass_delete(
                pkginfo_list, request.user,
                delete_pkgs=json_data.get('deletePkg', False)
            )
        except FileError as err:
            return HttpResponse(
                json.dumps({'result': 'failed',
                            'exception_type': str(type(err)),
                            'detail': str(err)}),
                content_type='application/json', status=403)
        else:
            return HttpResponse(
                json.dumps({'result': 'success'}),
                content_type='application/json')
    if request.method == 'POST':       
        # regular POST (update/change)
        LOGGER.info("Got mass update request for pkginfos")
        if not request.user.has_perm('pkgsinfo.change_pkginfofile'):
            return HttpResponse(
                json.dumps({
                    'result': 'failed',
                    'exception_type': 'PkginfoEditPermissionDenied',
                    'detail': "Missing needed permissions"}),
                content_type='application/json', status=403)
        json_data = json.loads(request.body)
        pkginfo_list = json_data.get('pkginfo_list', [])
        catalogs_to_add = json_data.get('catalogs_to_add', [])
        LOGGER.debug('Adding catalogs: %s', catalogs_to_add)
        catalogs_to_delete = json_data.get('catalogs_to_delete', [])
        LOGGER.debug('Removing catalogs: %s', catalogs_to_delete)
        try:
            Pkginfo.mass_edit_catalogs(
                pkginfo_list, catalogs_to_add, catalogs_to_delete,
                request.user)
        except FileError as err:
            return HttpResponse(
                json.dumps({'result': 'failed',
                            'exception_type': str(type(err)),
                            'detail': str(err)}),
                content_type='application/json', status=403)
        else:
            return HttpResponse(
                json.dumps({'result': 'success'}),
                content_type='application/json')


@login_required
def detail(request, pkginfo_path):
    '''Return detail for a specific pkginfo'''
    if request.method == 'GET':
        LOGGER.debug("Got read request for %s", pkginfo_path)
        try:
            plist = MunkiRepo.read('pkgsinfo', pkginfo_path)
        except FileDoesNotExistError:
            raise Http404("%s does not exist" % pkginfo_path)
        default_items = {
            'display_name': '',
            'description': '',
            'category': '',
            'developer': '',
            'unattended_install': False,
            'unattended_uninstall': False
        }
        for item in default_items:
            if not item in plist:
                plist[item] = default_items[item]
        pkginfo_text = plistlib.dumps(plist).decode()
        installer_item_path = plist.get('installer_item_location', '')
        icon_url = get_icon_url(plist)
        context = {'plist_text': pkginfo_text,
                   'pathname': pkginfo_path,
                   'installer_item_path': installer_item_path,
                   'icon_url': icon_url}
        return render(request, 'pkgsinfo/detail.html', context=context)
    if request.method == 'POST':
        return HttpResponse(
            json.dumps({'result': 'failed',
                        'exception_type': 'MethodNotSupported',
                        'detail': 'POST/PUT/DELETE should use the API'}),
            content_type='application/json', status=404)


def list_available_packages_json(request):
    """Returns a JSON list of available packages with their versions"""

    catalog = []
    try:
        catalogs_to_display = settings.CATALOGS_TO_DISPLAY
    except:
        catalogs_to_display = []

    for catalog_to_display in catalogs_to_display:
        catalog += MunkiRepo.read('catalogs', catalog_to_display)

    package_dict = {}

    for item in catalog:
        package_name = item['name']

        if package_name in package_dict:
            existing_package = package_dict[package_name]
            catalogs = item.get('catalogs', [])

            for catalog in catalogs:
                if catalog not in catalogs_to_display:
                    continue

                catalog_version = {
                    'name': catalog,
                    'version': item['version']
                }

                for existing_catalog in existing_package['catalogs']:
                    if existing_catalog['name'] == catalog:
                        existing_catalog['version'] = item['version']
                        break
                else:
                    existing_package['catalogs'].append(catalog_version)

        else:

            display_name = item.get('display_name')
            if display_name is None or display_name == '':
                display_name = item['name']

            package_item = {
                'name': item['name'],
                'display_name': display_name,
                'version': item['version'],
                'developer': item.get('developer', None),
                'categorie': item.get('categorie', None),
                'catalogs': [],
                'description': item.get('description', ''),
                'icon': None
            }

            catalogs = item.get('catalogs', [])
            for catalog in catalogs:
                if catalog not in catalogs_to_display:
                    continue
                catalog_version = {'name': catalog, 'version': item['version']}
                package_item['catalogs'].append(catalog_version)

            # Load the icon as a Base64-encoded string
            if SHOW_ICONS:
                icon_name = item.get('icon_name', item['name'] + '.png')
                icon_list = MunkiRepo.list('icons')

                if icon_name in icon_list:
                    icon_path = MunkiRepo.get('icons', icon_name)
                    package_item['icon'] = f"data:image/png;base64,{base64.b64encode(icon_path).decode('utf-8')}"
                        
            package_dict[package_name] = package_item

    return JsonResponse({"data": list(package_dict.values())}, safe=False)

def list_available_packages(request):
    context = {'page': 'packages',
               'show_icons': SHOW_ICONS }
    return render(request, 'pkgsinfo/package_list.html', context=context)