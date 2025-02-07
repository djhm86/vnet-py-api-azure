# __init__.py (Your Azure Function code)
import logging
import json
import os
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.cosmosdb.tables import TableClient  # or from azure.storage.table import TableService
#from azure.storage.table import TableService  # Older SDK

# Function to create VNet
def create_vnet(resource_group_name, vnet_name, location, address_prefix, subnet_specs):
    """Creates a VNet with multiple subnets."""

    credential = DefaultAzureCredential()
    network_client = NetworkManagementClient(credential, os.environ["AZURE_SUBSCRIPTION_ID"])

    vnet_params = {
        "location": location,
        "address_space": {"address_prefixes": [address_prefix]},
    }

    poller = network_client.virtual_networks.begin_create_or_update(
        resource_group_name, vnet_name, vnet_params
    )
    vnet_result = poller.result()
    logging.info(f"VNet {vnet_name} created/updated.")

    # Create Subnets
    for subnet_name, subnet_prefix in subnet_specs.items():
        subnet_params = {"address_prefix": subnet_prefix}
        poller = network_client.subnets.begin_create_or_update(
            resource_group_name, vnet_name, subnet_name, subnet_params
        )
        subnet_result = poller.result()
        logging.info(f"Subnet {subnet_name} created in VNet {vnet_name}.")

    return vnet_result  # or return a more detailed object

# Function to store VNet data in Azure Table Storage
def store_vnet_data(vnet_name, resource_group_name, location, address_prefix, subnet_specs):
    """Stores VNet information in Azure Table Storage."""

    table_name = "vnets"  # You can configure this
    #connection_string = os.environ["AzureWebJobsStorage"]  # Use the Function App's storage account
    account_name = os.environ["TABLE_ACCOUNT_NAME"]
    account_key = os.environ["TABLE_ACCOUNT_KEY"]

    #table_service = TableService(account_name=account_name, account_key=account_key) # Older SDK
    #table_service.create_table_if_not_exists(table_name) # Older SDK

    table_client = TableClient(account_url=f"https://{account_name}.table.core.windows.net", table_name=table_name, credential=DefaultAzureCredential())
    try:
        table_client.create_table()
    except Exception as e:
        logging.warning(f"Table might already exist or other error: {e}")


    entity = {
        "PartitionKey": resource_group_name,  # Group by resource group
        "RowKey": vnet_name,  # Unique VNet name
        "location": location,
        "address_prefix": address_prefix,
        "subnets": json.dumps(subnet_specs),  # Store subnets as JSON
    }

    #table_service.insert_entity(table_name, entity) # Older SDK
    table_client.upsert_entity(entity=entity)

    logging.info(f"VNet data stored in Table Storage for {vnet_name}.")

# Function to retrieve VNet data from Azure Table Storage
def get_vnet_data(resource_group_name, vnet_name):
    """Retrieves VNet information from Azure Table Storage."""

    table_name = "vnets"
    #connection_string = os.environ["AzureWebJobsStorage"]
    account_name = os.environ["TABLE_ACCOUNT_NAME"]
    account_key = os.environ["TABLE_ACCOUNT_KEY"]

    #table_service = TableService(account_name=account_name, account_key=account_key) # Older SDK

    #entity = table_service.get_entity(table_name, resource_group_name, vnet_name) # Older SDK
    table_client = TableClient(account_url=f"https://{account_name}.table.core.windows.net", table_name=table_name, credential=DefaultAzureCredential())
    try:
      entity = table_client.get_entity(partition_key=resource_group_name, row_key=vnet_name)
      entity['subnets'] = json.loads(entity['subnets'])  # Convert JSON back to dict
      return entity
    except Exception as e:
      logging.warning(f"Error retrieving entity: {e}")
      return None


# Azure Function entry point
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
             "Please pass a JSON payload in the request body",
             status_code=400
        )

    operation = req_body.get('operation')

    if operation == 'create_vnet':
        resource_group_name = req_body.get('resource_group_name')
        vnet_name = req_body.get('vnet_name')
        location = req_body.get('location')
        address_prefix = req_body.get('address_prefix')
        subnet_specs = req_body.get('subnet_specs')  # {"subnet1": "10.0.1.0/24", "subnet2": "10.0.2.0/24"}

        if not all([resource_group_name, vnet_name, location, address_prefix, subnet_specs]):
            return func.HttpResponse(
                 "Missing parameters for VNet creation",
                 status_code=400
            )

        try:
            vnet_result = create_vnet(resource_group_name, vnet_name, location, address_prefix, subnet_specs)
            store_vnet_data(vnet_name, resource_group_name, location, address_prefix, subnet_specs)  # Store the data
            return func.HttpResponse(
                json.dumps({
                    "message": f"VNet {vnet_name} created successfully.",
                    "vnet": {
                        "name": vnet_result.name,
                        "id": vnet_result.id,
                        # Add other relevant attributes
                    }
                }),
                mimetype="application/json",
                status_code=200
            )
        except Exception as e:
            logging.exception(f"Error creating VNet: {e}")
            return func.HttpResponse(
                 f"Error creating VNet: {e}",
                 status_code=500
            )

    elif operation == 'get_vnet':
        resource_group_name = req_body.get('resource_group_name')
        vnet_name = req_body.get('vnet_name')

        if not all([resource_group_name, vnet_name]):
             return func.HttpResponse(
                 "Missing parameters for VNet retrieval",
                 status_code=400
            )

        vnet_data = get_vnet_data(resource_group_name, vnet_name)

        if vnet_data:
            return func.HttpResponse(
                json.dumps(vnet_data),
                mimetype="application/json",
                status_code=200
            )
        else:
            return func.HttpResponse(
                "VNet not found",
                status_code=404
            )

    else:
        return func.HttpResponse(
             "Invalid operation.  Use 'create_vnet' or 'get_vnet'.",
             status_code=400
        )