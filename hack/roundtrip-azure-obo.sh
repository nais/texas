#!/bin/bash -e
user_token_response=$(curl -s -X POST http://localhost:8080/azuread/token -d "grant_type=authorization_code&code=yolo&client_id=yolo&client_secret=bolo")

user_token=$(echo ${user_token_response} | jq -r .access_token)

response=$(curl -s -X POST http://localhost:3000/api/v1/token/exchange -H "content-type: application/json" -d '{"target": "client-id", "identity_provider": "azuread", "user_token": "'${user_token}'"}')
token=$(echo ${response} | jq -r .access_token)

validation=$(curl -s -X POST http://localhost:3000/api/v1/introspect -H "content-type: application/json" -d "{\"token\": \"${token}\", \"identity_provider\": \"azuread\"}")

echo
echo "User token:"
echo "${user_token}"

echo
echo "JWT:"
echo "${response}" | jq -S .

echo
echo "Validation:"
echo "${validation}" | jq -S .
