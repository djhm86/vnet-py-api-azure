# vnet-py-api-azure
These APIs will create and manage vnets and subnets in Azure.
They are deployed on a Azure function app.

Overall Architecture

1. Azure Function App: The core of these APIs. It will expose HTTP endpoints to receive requests, process them, and return responses.2
2. azure-mgmt-network: The Python SDK for managing Azure Networking resources (VNets, Subnets, etc.).
3. User Input: The API will accept parameters like VNet name, location, address prefixes, and a specification for the subnets (names, address prefixes). An existing resource group with need to be provided to it.
4. Data Persistence: Will need a storage mechanism to store the details of the created VNets and subnets. Azure Table Storage, Cosmos DB, or even Azure SQL Database are good choices. I'll use Azure Table Storage for simplicity.
5. Authentication/Authorization: Azure Functions has built-in authentication/authorization features. We'll enable Azure Active Directory (Azure AD) authentication. Authorization will be configured to allow any authenticated user to access the API.
   
You can locally setup azure functions by cloing this repo and by running the following steps and commands at application root folder. Also place a localsettings.json file with the following contents:

```json
{
  "IsEncrypted": false,
  "Values": {
      "AzureWebJobsStorage": "",
      "FUNCTIONS_WORKER_RUNTIME": "python",
      "AZURE_SUBSCRIPTION_ID": "<Your subscription ID>",
      "KEY_VAULT_URL": "<Key Vault URL in case storing secrets in KV>",
      "AZURE_CLIENT_ID": "<Azure AD App registeration Client (app) ID>",
      "AZURE_TENANT_ID":"<Azure AD Tenant ID>",
      "AZURE_STORAGE_CONN":"<Connection string for the Azure Table Storage account>",
      "AZURE_CLIENT_SECRET":"<Secret created for the app registeration in Azure AD>"

  }
```
Ignore this file, and include similar environment varibles in the application settings of Azure Function App when deploying there.

Install the Azure Functions Core Tools along with Azure CLI.

Create and activate a virtual environment

```console
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
Start the functions written in function_app.py
```console
func start
```
You can access the functions running in your localhost through the URLs displayed after running this command. Something like - http://localhost:7071/api/create_vnet

Deploy to Azure

```console
#As a prerequisite, create a storage account with fileshare and then create an Azure function app using below.
az functionapp create --resource-group MyResourceGroup --consumption-plan-location eastus --runtime python --name vnet-api-app --os-type Linux --storage-account mystorageaccount
#Deploy the function using the below command or using zip deployment through github actions
func azure functionapp publish my-fastapi-app
#Get Function App URL
az functionapp show --name vet-api-app --resource-group MyResourceGroup --query defaultHostName -o tsv
```

Implementing Azure AD Authentication for an API in Azure Function App V2
Prerequisites
1. Azure CLI installed (az --version)
2. Azure Function App V2 deployed
3. Azure Active Directory (AAD) App Registration set up

```console
#Create an Azure AD App
az ad app create --display-name "AzureFunctionAPI" --identifier-uris "api://AzureFunctionAPI"
#Create a Service Principal
az ad sp create --id <APPLICATION_ID>
#Create a client secret
az ad app credential reset --id <APPLICATION_ID> --append
```
In App registerations in Azure AD, under API permissions, provide User.Read and User.Write permission to your API application.

Configure Azure Function App for AAD Authentication
```console
az functionapp update --name <YOUR_FUNCTION_APP> --resource-group <YOUR_RESOURCE_GROUP> --set authSettings.enabled=true
az functionapp auth update --name <YOUR_FUNCTION_APP> --resource-group <YOUR_RESOURCE_GROUP> --set authSettings.unauthenticatedClientAction=RedirectToLoginPage
```
In the Azure Portal:

Go to Function App → Authentication.
Enable Authentication and select Microsoft Identity Platform.
Set Allowed Audiences to api://AzureFunctionAPI.

Test the Authentication
```console
az account get-access-token --resource api://AzureFunctionAPI
```
Call the Secure API
Replace <ACCESS_TOKEN> with the token from the previous step:
```console
curl -X GET "https://<YOUR_FUNCTION_APP>.azurewebsites.net/api/get_vnets?resource_group=<resource-group-name>" \
     -H "Authorization: Bearer <ACCESS_TOKEN>"
```
Expected correct response (HTTP-200) will provide list of vnets which have been created using the create-vnet api of the function app.



This implementation provides two Azure Functions:

1. create_vnet: Creates a VNET with multiple subnets

Method: POST
Requires authentication token in Authorization header
Request body example:
```console
{
    "resource_group": "my-resource-group",
    "vnet_name": "my-vnet",
    "location": "eastus",
    "address_space": "10.0.0.0/16",
    "subnets": [
        {
            "name": "subnet1",
            "address_prefix": "10.0.0.0/24"
        },
        {
            "name": "subnet2",
            "address_prefix": "10.0.1.0/24"
        }
    ]
}
```
2. get_vnets: Retrieves all VNETs in a resource group

Method: GET
Requires authentication token in Authorization header
Query parameter: resource_group

Example to invoke create vnet API - 

```console
az account get-access-token --resource api://AzureFunctionAPI
```
Call the Secure API
Replace <ACCESS_TOKEN> with the token from the previous step:
```console
curl -X GET "https://vnet-api-app.azurewebsites.net/api/create_vnet" \
     -H "Authorization: Bearer <ACCESS_TOKEN>" -H "Content-Type: application/json" --data '{"resource_group":"my-resource-group","vnet_name":"my-vnet","location":"eastus","address_space":"10.0.0.0/16","subnets":[{"name":"subnet1","address_prefix":"10.0.0.0/24"},{"name":"subnet2","address_prefix":"10.0.1.0/24"}]}'
```
Expected correct response (HTTP-200) will return the details of the just created vnet using create_vnet api of the function app.

Example to invoke get vnet API- 
```console
az account get-access-token --resource api://AzureFunctionAPI
```
Call the Secure API
Replace <ACCESS_TOKEN> with the token from the previous step:
```console
curl -X GET "https://vnet-api-app.azurewebsites.net.azurewebsites.net/api/get_vnets?resource_group=my-resource-group" \
     -H "Authorization: Bearer <ACCESS_TOKEN>"
```

Expected correct response (HTTP-200) will provide list of vnets which have been created using the create-vnet api of the function app.