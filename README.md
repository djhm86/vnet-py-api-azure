# vnet-py-api-azure
These APIs will create and manage vnets and subnets in Azure.
They are deployed on a Azure function app.

Overall Architecture

Azure Function App: The core of these APIs. It will expose HTTP endpoints to receive requests, process them, and return responses.
azure-mgmt-network: The Python SDK for managing Azure Networking resources (VNets, Subnets, etc.).
User Input: The API will accept parameters like VNet name, location, address prefixes, and a specification for the subnets (names, address prefixes). An existing resource group with need to be provided to it.
Data Persistence: Will need a storage mechanism to store the details of the created VNets and subnets. Azure Table Storage, Cosmos DB, or even Azure SQL Database are good choices. I'll use Azure Table Storage for simplicity.
Authentication/Authorization: Azure Functions has built-in authentication/authorization features. We'll enable Azure Active Directory (Azure AD) authentication. Authorization will be configured to allow any authenticated user to access the API.

