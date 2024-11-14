#!/bin/bash -e
user_token_response=$(curl -s -X POST http://localhost:8080/idporten/token -d "grant_type=authorization_code&code=yolo&client_id=yolo&client_secret=bolo")
user_token=$(echo ${user_token_response} | jq -r .access_token)

validation=$(curl -s -X POST http://localhost:3000/api/v1/introspect -H "content-type: application/json" -d "{\"token\": \"${user_token}\", \"identity_provider\": \"idporten\"}")

echo
echo "User token:"
echo "${user_token}"

echo
echo "Validation:"
echo "${validation}" | jq -S .
