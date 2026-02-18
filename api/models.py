"""
api/models.py
"""
from django.conf import settings

import sys
import logging
import platform

LOGGER = logging.getLogger('munkiwebadmin')
MUNKI_REPO_URL = settings.MUNKI_REPO_URL
MUNKI_REPO_PLUGIN = settings.MUNKI_REPO_PLUGIN
MUNKITOOLS_DIR = settings.MUNKITOOLS_DIR

# import munkitools
sys.path.append(MUNKITOOLS_DIR)

try:
    from munkilib.admin import makecatalogslib
    from munkilib.wrappers import (readPlistFromString, writePlistToString)
    from munkilib import munkirepo
except ImportError:
    LOGGER.error('Failed to import munkilib')
    raise

if platform.system() == "Darwin":
    from munkilib.admin.munkiimportlib import find_matching_pkginfo
else:
    from api.utils.munkiimport_linux import find_matching_pkginfo


# connect to the munki repo
_repo = None
_repo_error = None


def get_repo():
    """Return a connected Munki repo.

    Important: repo connections can fail (e.g. expired Azure SAS token). We keep
    the module importable so Django can start and surface a runtime error
    instead of crashing during app startup.
    """
    global _repo, _repo_error

    if _repo is not None:
        return _repo
    if _repo_error is not None:
        raise _repo_error

    try:
        _repo = munkirepo.connect(MUNKI_REPO_URL, MUNKI_REPO_PLUGIN)
        return _repo
    except Exception as err:  # noqa: BLE001 - repo plugins can throw non-RepoError exceptions
        _repo_error = err
        LOGGER.exception('Repo connection failed (plugin=%s url=%s)', MUNKI_REPO_PLUGIN, MUNKI_REPO_URL)
        raise


class FileError(Exception):
    '''Class for file errors'''
    pass


class FileReadError(FileError):
    '''Error reading a file'''
    pass


class FileWriteError(FileError):
    '''Error writing a file'''
    pass


class FileDeleteError(FileError):
    '''Error deleting a file'''
    pass


class FileDoesNotExistError(FileError):
    '''Error when file doesn't exist at pathname'''
    pass


class FileAlreadyExistsError(FileError):
    '''Error when creating a new file at an existing pathname'''
    pass


class MunkiRepo(object):
    '''Pseudo-Django object'''
    @classmethod
    def list(cls, kind):
        '''Returns a list of available plists'''
        repo = get_repo()
        plists = repo.itemlist(kind)
        return plists
    
    @classmethod
    def get(cls, kind, pathname):
        '''Reads a file and returns the contents'''
        try:
            repo = get_repo()
            return repo.get(kind + '/' + pathname)
        except munkirepo.RepoError as err:
            LOGGER.error('Read failed for %s/%s: %s', kind, pathname, err)
            raise FileReadError(err)

    @classmethod
    def read(cls, kind, pathname):
        '''Reads a plist file and returns the plist as a dictionary'''
        try:
            repo = get_repo()
            return readPlistFromString(repo.get(kind + '/' + pathname))
        except munkirepo.RepoError as err:
            LOGGER.error('Read failed for %s/%s: %s', kind, pathname, err)
            raise FileReadError(err)
    
    @classmethod
    def write(cls, data, kind, pathname):
        '''Writes a text data to (plist) file'''
        try:
            repo = get_repo()
            repo.put(kind + '/' + pathname, writePlistToString(data))
            LOGGER.info('Wrote %s/%s', kind, pathname)
        except munkirepo.RepoError as err:
            LOGGER.error('Write failed for %s/%s: %s', kind, pathname, err)
            raise FileWriteError(err)
        
    @classmethod
    def writedata(cls, data, kind, pathname):
        '''Writes a text data to file'''
        try:
            repo = get_repo()
            repo.put(kind + '/' + pathname, data)
            LOGGER.info('Wrote %s/%s', kind, pathname)
        except munkirepo.RepoError as err:
            LOGGER.error('Write failed for %s/%s: %s', kind, pathname, err)
            raise FileWriteError(err)
    
    @classmethod
    def delete(cls, kind, pathname):
        '''Deletes a plist file'''
        try:
            repo = get_repo()
            repo.delete(kind + '/' + pathname)
            LOGGER.info('Deleted %s/%s', kind, pathname)
        except munkirepo.RepoError as err:
            LOGGER.error('Delete failed for %s/%s: %s', kind, pathname, err)
            raise FileDeleteError(err)
    
    @classmethod
    def makecatalogs(cls, output_fn=None):
        '''Calls makecatalogs'''
        try:
            repo = get_repo()
            makecatalogslib.makecatalogs(repo, {}, output_fn=output_fn)
        except makecatalogslib.MakeCatalogsError as err:
            LOGGER.error('makecatalogs failed: %s', err)
            raise FileError(err)
        
    @classmethod
    def find_matching_pkginfo(cls, pkginfo):
        '''Returns a list of pkginfo items matching a given match string'''
        repo = get_repo()
        return find_matching_pkginfo(repo, pkginfo)