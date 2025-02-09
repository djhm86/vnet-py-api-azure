# function_app.py
import azure.functions as func
import logging
import json
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import VirtualNetwork, Subnet
import os
from jose import jwt
from datetime import datetime
from typing import List, Dict
from azure.data.tables import TableServiceClient
app = func.FunctionApp()

def get_jwt_secret():
    key_vault_url = os.environ['KEY_VAULT_URL']
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=key_vault_url, credential=credential)
    return secret_client.get_secret("jwt-secret-key").value

def require_auth(req: func.HttpRequest) -> bool:
    try:
        auth_header = req.headers.get('Authorization')
        if not auth_header:
            return False
        
        token = auth_header.split(' ')[1]
        jwt_secret = get_jwt_secret()
        
        decoded = jwt.decode(
            token,
            jwt_secret,
            algorithms=['HS256']
        )
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