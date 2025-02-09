from jose import jwt
import datetime
import requests
import os

def create_auth_token(user_id: str) -> str:
    # Get secret key from environment variable
    secret_key = "y6N8Q~rmKd~DhPBUM9HbGnKP4Y8yTbroyDQUbcA6"
    
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        'iat': datetime.datetime.utcnow()
    }
    
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token

# Usage in HTTP client
headers = {
    'Authorization': f'Bearer {create_auth_token("0f1a1605-c8a0-4e11-b8a9-518e9713724f")}',
    'Content-Type': 'application/json'
}
vnet_data = {
    "resource_group": "my-resource-group",
    "vnet_name": "my-vnet1",
    "location": "eastus",
    "address_space": "10.0.0.0/16",
    "subnets": [
        {
            "name": "subnet1",
            "address_prefix": "10.0.0.0/29"
        },
        {
            "name": "subnet2",
            "address_prefix": "10.0.1.0/24"
        }
    ]
}
# Example request
#response = requests.post('http://localhost:7071/api/create_vnet', headers=headers, json=vnet_data)

params_payload = {'resource_group':'my-resource-group'}

response = requests.get('http://localhost:7071/api/get_vnets', headers=headers, params=params_payload)
print (response.content)
print (response.status_code)