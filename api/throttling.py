"""
API Throttling Classes
"""
from rest_framework.throttling import UserRateThrottle


class UploadRateThrottle(UserRateThrottle):
    """
    Throttle for package uploads - more restrictive than general API calls
    """
    scope = 'uploads'
