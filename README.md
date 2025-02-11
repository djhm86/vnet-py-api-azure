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


