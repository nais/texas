#!/bin/bash -e
response=$(curl -s -X POST http://localhost:3000/api/v1/token -H "content-type: application/json" -d '{"target": "my-target", "identity_provider": "maskinporten"}')
token=$(echo ${response} | jq -r .access_token)
validation=$(curl -s -X POST http://localhost:3000/api/v1/introspect -H "content-type: application/json" -d "{\"token\": \"${token}\", \"identity_provider\": \"maskinporten\"}")

echo
echo "JWT:"
echo "${response}" | jq -S .

echo
echo "Validation:"
echo "${validation}" | jq -S .
