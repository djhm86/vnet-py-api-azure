# function_app.py
import azure.functions as func
import logging
import json
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import VirtualNetwork, Subnet
import os
#from jose import jwt
import jwt
from datetime import datetime
from typing import List, Dict
from azure.data.tables import TableServiceClient
#import msal
import requests

app = func.FunctionApp()

logging.basicConfig(level=logging.INFO, filename="py_log.log",filemode="w")

# def get_jwt_secret():
#     key_vault_url = os.environ['KEY_VAULT_URL']
#     credential = DefaultAzureCredential()
#     secret_client = SecretClient(vault_url=key_vault_url, credential=credential)
#     return secret_client.get_secret("jwt-secret-key").value

# def get_access_token():
#     try:
#         client_id = os.environ['AZURE_CLIENT_ID']
#         client_secret = get_jwt_secret()
#         tenant_id = os.environ['AZURE_TENANT_ID']
        
#         # Initialize MSAL client
#         authority = f"https://login.microsoftonline.com/{tenant_id}"
#         app = msal.ConfidentialClientApplication(
#             client_id,
#             authority=authority,
#             client_credential=client_secret
#         )
        
#         # Get token using client credentials flow
#         scopes = ['https://management.azure.com/.default']
#         result = app.acquire_token_for_client(scopes=scopes)
        
#         if 'access_token' in result:
#             return result['access_token']
#         else:
#             raise Exception(f"Error getting token: {result.get('error_description')}")
            
#     except Exception as e:
#         logging.error(f"Error getting access token: {str(e)}")
#         raise

# def require_auth(req: func.HttpRequest) -> bool:
#     try:
#         auth_header = req.headers.get('Authorization')
#         if not auth_header:
#             return False
        
#         token = auth_header.split(' ')[1]
        
#         # Validate token against Azure AD
#         tenant_id = os.environ['AZURE_TENANT_ID']
#         validation_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/keys"
        
#         try:
#             decoded = jwt.decode(
#                 token,
#                 requests.get(validation_url).json(),
#                 algorithms=['RS256'],
#                 audience=os.environ['AZURE_CLIENT_ID']
#             )
#             return True
#         except Exception as e:
#             logging.error(f"Token validation error: {str(e)}")
#             return False
            
#     except Exception as e:
#         logging.error(f"Authentication error: {str(e)}")
#         return False

# Load Azure AD details from environment variables
TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
API_AUDIENCE = "api://AzureFunctionAPI"
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

def get_jwks():
    """Retrieve JWKS (JSON Web Key Set) from Azure AD for JWT validation."""
    response = requests.get(JWKS_URL)
    return response.json()

def decode_jwt(token: str):
    """Validate and decode JWT token from Azure AD."""
    try:
        jwks = get_jwks()
        header = jwt.get_unverified_header(token)
        key = next((k for k in jwks["keys"] if k["kid"] == header["kid"]), None)

        if not key:
            raise Exception("Invalid token")

        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
        payload = jwt.decode(token, public_key, algorithms=["RS256"], audience=API_AUDIENCE)
        return payload

    except jwt.ExpiredSignatureError:
        raise Exception("Token expired")
    #except jwt.InvalidTokenError:
    #    raise Exception("Invalid token")

def require_auth(req: func.HttpRequest) -> bool:
    """Azure Function HTTP trigger for secure API endpoint."""
    logging.info("Processing request...")

    # Extract Authorization header
    auth_header = req.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        logging.error (f"Missing or invalid Authorization header")
        return False
    # Extract token
    token = auth_header.split(" ")[1]

    try:
        user_info = decode_jwt(token)
        return True

    except Exception as e:
        logging.error(f"Authentication error: {str(e)}")
        return False

def get_network_client():
    credential = DefaultAzureCredential()
    subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
    return NetworkManagementClient(credential, subscription_id)

def get_storage_connection():
    key_vault_url = os.environ['KEY_VAULT_URL']
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=key_vault_url, credential=credential)
    return secret_client.get_secret("storage-connection-string").value


@app.route(route="create_vnet", auth_level="anonymous")
async def create_vnet(req: func.HttpRequest) -> func.HttpResponse:
    if not require_auth(req):
        return func.HttpResponse(
            "Unauthorized",
            status_code=401
        )
    
    try:
        req_body = req.get_json()
        resource_group = req_body.get('resource_group')
        vnet_name = req_body.get('vnet_name')
        location = req_body.get('location')
        address_space = req_body.get('address_space')
        subnet_configs = req_body.get('subnets', [])
        
        if not all([resource_group, vnet_name, location, address_space, subnet_configs]):
            return func.HttpResponse(
                "Missing required parameters",
                status_code=400
            )
        
        network_client = get_network_client()
        
        # Create subnets configuration
        subnets = []
        for subnet in subnet_configs:
            subnets.append(
                Subnet(
                    name=subnet['name'],
                    address_prefix=subnet['address_prefix']
                )
            )
        
        # Create VNET
        vnet_params = VirtualNetwork(
            location=location,
            address_space={'address_prefixes': [address_space]},
            subnets=subnets
        )
        
        poller = network_client.virtual_networks.begin_create_or_update(
            resource_group,
            vnet_name,
            vnet_params
        )
        vnet = poller.result()
        
        # Store VNET info in Azure Table Storage
        store_vnet_info(vnet, resource_group)
        
        return func.HttpResponse(
            json.dumps({
                "id": vnet.id,
                "name": vnet.name,
                "location": vnet.location,
                "address_space": vnet.address_space.address_prefixes,
                "subnets": [{"name": subnet.name, "address_prefix": subnet.address_prefix} 
                           for subnet in vnet.subnets]
            }),
            mimetype="application/json"
        )
        
    except Exception as e:
        logging.error(f"Error creating VNET: {str(e)}")
        return func.HttpResponse(
            f"Error creating VNET: {str(e)}",
            status_code=500
        )

def store_vnet_info(vnet, resource_group):
    try:
        # Get external storage account credentials from environment variables
        connection_string = get_storage_connection()
        
        table_service = TableServiceClient.from_connection_string(connection_string)
        table_client = table_service.get_table_client('vnets')
        
        # Create table if it doesn't exist
        try:
            table_service.create_table('vnets')
        except:
            pass
        
        # Prepare entity data
        entity = {
            'PartitionKey': resource_group,
            'RowKey': vnet.name,
            'ID': vnet.id,
            'Location': vnet.location,
            'AddressSpace': json.dumps(vnet.address_space.address_prefixes),
            'Subnets': json.dumps([{
                'name': subnet.name,
                'address_prefix': subnet.address_prefix
            } for subnet in vnet.subnets]),
            'Timestamp': datetime.utcnow().isoformat()
        }
        
        table_client.upsert_entity(entity)
        
    except Exception as e:
        logging.error(f"Error storing VNET info: {str(e)}")
        raise     

@app.route(route="get_vnets", auth_level="anonymous")
async def get_vnets(req: func.HttpRequest) -> func.HttpResponse:
    if not require_auth(req):
        return func.HttpResponse(
            "Unauthorized",
            status_code=401
        )
    
    try:
        resource_group = req.params.get('resource_group')
        if not resource_group:
            return func.HttpResponse(
                "Resource group parameter is required",
                status_code=400
            )
        
        connection_string = get_storage_connection()
        table_service = TableServiceClient.from_connection_string(connection_string)
        table_client = table_service.get_table_client('vnets')
        
        # Query entities by resource group (PartitionKey)
        entities = table_client.query_entities(f"PartitionKey eq '{resource_group}'")
        
        vnet_list = []
        for entity in entities:
            vnet_list.append({
                "id": entity['ID'],
                "name": entity['RowKey'],
                "location": entity['Location'],
                "address_space": json.loads(entity['AddressSpace']),
                "subnets": json.loads(entity['Subnets']),
                "created_at": entity._metadata["timestamp"].isoformat()
            })
        
        return func.HttpResponse(
            json.dumps(vnet_list),
            mimetype="application/json"
        )
        
    except Exception as e:
        logging.error(f"Error retrieving VNETs: {str(e)}")
        return func.HttpResponse(
            f"Error retrieving VNETs: {str(e)}",
            status_code=500
        )
