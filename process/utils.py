''' process/utils.py '''
from .models import Process
from django.db.utils import OperationalError

def record_status(processname, message=None, percent_done=None):
    '''Record process feedback so we can display it during long-running
    operations'''
    # If the database hasn't been migrated yet (common with fresh SQLite DBs),
    # the Process table may not exist. Status tracking is non-critical, so
    # don't fail the calling view.
    try:
        proc_rec = Process.objects.get(name=processname)
    except OperationalError:
        return
    except Process.DoesNotExist:
        proc_rec = Process(name=processname)
    if message:
        proc_rec.statustext = message
    if percent_done:
        proc_rec.percentdone = percent_done
    proc_rec.save()
