# slack.py
import datetime
import json
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
import hashlib

import requests
from fastapi import Request
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from integrations.integration_item import IntegrationItem


CLIENT_ID = '05c7defb-efd5-47dd-bcf1-65e2176b192b'
CLIENT_SECRET = 'c5b3e60a-01ff-45a1-9a93-84883f2835ea'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
authorization_url = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri=http://localhost:8000/integrations/hubspot/oauth2callback&scope=oauth%20crm.objects.contacts.read'

encoded_client_id_secret = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()
scope = 'data.records:read data.records:write data.recordComments:read data.recordComments:write schema.bases:read schema.bases:write'




async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')

    code_verifier = secrets.token_urlsafe(32)
    m = hashlib.sha256()
    m.update(code_verifier.encode('utf-8'))
    code_challenge = base64.urlsafe_b64encode(m.digest()).decode('utf-8').replace('=', '')

    auth_url = f'{authorization_url}&state={encoded_state}&code_challenge={code_challenge}&code_challenge_method=S256&scope={scope}'
    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600),
        add_key_value_redis(f'hubspot_verifier:{org_id}:{user_id}', code_verifier, expire=600),
    )
    return auth_url

async def oauth2callback_hubspot(request: Request):
    # Handle errors returned from HubSpot's authorization server
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    
    # Extract query parameters
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    # Retrieve saved state and code verifier from Redis
    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f'hubspot_state:{org_id}:{user_id}'),
        get_value_redis(f'hubspot_verifier:{org_id}:{user_id}'),
    )

    # Verify state
    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    # Exchange authorization code for tokens
    async with httpx.AsyncClient() as client:
        response, _, _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                    'code_verifier': code_verifier.decode('utf-8'),
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
            delete_key_redis(f'hubspot_verifier:{org_id}:{user_id}'),
        )

    # Save HubSpot credentials in Redis
    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600)
    
    # HTML response to close the authorization window
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)


async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

def create_integration_item_metadata_object(
    response_json: dict, item_type: str, parent_id=None, parent_name=None
) -> IntegrationItem:
    # Append a suffix to the parent_id if provided
    parent_id = None if parent_id is None else parent_id + '_Parent'

    # Extract name from `properties` or provide a default fallback
    name = response_json.get('properties', {}).get('name', f"Unnamed {item_type}")

    # Construct and return the IntegrationItem
    integration_item_metadata = IntegrationItem(
        id=response_json.get('id', '') + '_' + item_type,
        name=name,
        type=item_type,
        parent_id=parent_id,
        parent_path_or_name=parent_name,
    )

    return integration_item_metadata


async def get_items_hubspot(credentials) -> list[IntegrationItem]:
    credentials = json.loads(credentials)
    access_token = credentials.get('access_token')
    base_url = 'https://api.hubapi.com'
    list_of_integration_item_metadata = []
    
    # Endpoints to fetch various items (e.g., pipelines, deals, etc.)
    endpoints = [
        '/crm/v3/objects/pipelines/deals',  # Example: Deal Pipelines
        '/crm/v3/objects/deals',           # Example: Deals
        '/crm/v3/objects/contacts',        # Example: Contacts
    ]
    
    headers = {'Authorization': f'Bearer {access_token}'}
    
    async with httpx.AsyncClient() as client:
        for endpoint in endpoints:
            url = f'{base_url}{endpoint}'
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                items = response.json().get('results', [])
                for item in items:
                    list_of_integration_item_metadata.append(
                        create_integration_item_metadata_object(item, endpoint.split('/')[-1])
                    )
            else:
                print(f"Failed to fetch from {url}: {response.status_code} - {response.text}")

    print(f'list_of_integration_item_metadata: {list_of_integration_item_metadata}')
    return list_of_integration_item_metadata
