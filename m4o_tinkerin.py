import requests
from requests.auth import HTTPDigestAuth
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

def connect_to_mongo():
    uri = "mongodb+srv://scrote:butcrax!!@m4o.y418idm.mongodb.net/?retryWrites=true&w=majority"

    # Create a new client and connect to the server
    client = MongoClient(uri, server_api=ServerApi('1'), ssl=True)

    # Send a ping to confirm a successful connection
    try:
        client.admin.command('ping')
        print("Pinged your deployment. You successfully connected to MongoDB!")
    except Exception as e:
        print(e)


def resolve_ip():

    atlas_group_id = "6525c7db763be01ca711d36b"
    atlas_api_key_public = "tnykhtwp"
    atlas_api_key_private = "17a46238-8afe-421b-a2fa-1ad1363f1df8"


    response = requests.get('https://api.ipify.org?format=json')
    ip = response.json().get('ip', None)
    if ip:
        print(ip)
    else:
        raise Exception('Failed to retrieve IP address from Ipify.')



    resp = requests.post(
        "https://cloud.mongodb.com/api/atlas/v1.0/groups/{atlas_group_id}/accessList".format(atlas_group_id=atlas_group_id),
        auth=HTTPDigestAuth(atlas_api_key_public, atlas_api_key_private),
        json=[{'ipAddress': ip, 'comment': 'From PythonAnywhere'}]  # the comment is optional
    )
    if resp.status_code in (200, 201):
        print("MongoDB Atlas accessList request successful", flush=True)
    else:
        print(
            "MongoDB Atlas accessList request problem: status code was {status_code}, content was {content}".format(
                status_code=resp.status_code, content=resp.content
            ),
            flush=True
        )
