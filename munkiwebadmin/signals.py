import requests
import logging
import base64
from django.dispatch import receiver
from django.conf import settings
from django_auth_adfs.signals import post_authenticate
from django.apps import apps  # Delayed model import for UserProfile

logger = logging.getLogger(__name__)

def get_graph_token(user_access_token):
    """
    Exchanges the user token for a Microsoft Graph API token using the On-Behalf-Of flow.
    """
    url = f"https://login.microsoftonline.com/{settings.TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": settings.CLIENT_ID,
        "client_secret": settings.CLIENT_SECRET,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": user_access_token,
        "scope": "https://graph.microsoft.com/.default",
        "requested_token_use": "on_behalf_of",
    }

    response = requests.post(url, data=data)
    if response.status_code == 200:
        graph_token = response.json().get("access_token")
        logger.info("Successfully retrieved Microsoft Graph access token.")
        return graph_token
    else:
        logger.error(f"Error retrieving Graph token: {response.status_code}, {response.text}")
        return None

def fetch_user_profile_picture(graph_token, user):
    """
    Retrieves the user's profile picture from Microsoft Graph API and stores it as Base64 in the database.
    """
    url = "https://graph.microsoft.com/v1.0/me/photo/$value"
    headers = {"Authorization": f"Bearer {graph_token}"}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        UserProfile = apps.get_model("munkiwebadmin", "UserProfile")
        user_profile, created = UserProfile.objects.get_or_create(user=user)

        # Convert image to Base64
        image_base64 = base64.b64encode(response.content).decode("utf-8")
        user_profile.profile_picture_base64 = image_base64
        user_profile.save()

        logger.info(f"Profile picture for {user.username} successfully stored in the database.")
    else:
        logger.warning(f"Error retrieving profile picture: {response.status_code} - {response.text}")

@receiver(post_authenticate)
def fetch_and_store_user_photo(sender, user, claims, adfs_response, **kwargs):
    """
    After authentication, this function retrieves the user's profile picture and stores it in the database.
    """
    access_token = adfs_response.get("access_token")
    if not access_token:
        logger.warning("No access token available, skipping profile picture update.")
        return

    # Retrieve a Microsoft Graph API token using On-Behalf-Of flow
    graph_token = get_graph_token(access_token)
    if graph_token:
        fetch_user_profile_picture(graph_token, user)
    else:
        logger.error("Failed to retrieve a valid Microsoft Graph token.")