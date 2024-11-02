#!/bin/bash -e
user_token_response=$(curl -s -X POST http://localhost:8080/azuread/token -d "grant_type=authorization_code&code=yolo&client_id=yolo&client_secret=bolo")
user_token=$(echo ${user_token_response} | jq -r .access_token)

response=$(curl -s -X POST http://localhost:3000/token -H "content-type: application/json" -d '{"target": "my-target", "identity_provider": "azuread", "user_token": "'${user_token}'"}')
token=$(echo ${response} | jq -r .access_token)

#validation=$(curl -s -X POST http://localhost:3000/introspect -H "content-type: application/json" -d "{\"token\": \"${token}\"}")

echo
echo "JWT:"
echo "${response}" | jq -S .

echo
echo "Validation:"
echo "${validation}" | jq -S .

