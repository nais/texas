#!/bin/bash -e
echo "Performing request with content-type: application/json"
response=$(curl -s -X POST http://localhost:3000/api/v1/token -H "content-type: application/json" -d '{"target": "my-target", "identity_provider": "maskinporten", "authorization_details": [{
    "type": "urn:altinn:systemuser",
    "systemuser_org": {
      "authority": "iso6523-actorid-upis",
      "ID": "0192:313367002"
    },
    "systemuser_id": [
      "33a0911a-5459-456f-bc57-3d37ef9a016c"
    ],
    "system_id": "974761076_skatt_demo_system"
  }]
}')
token=$(echo ${response} | jq -r .access_token)
validation=$(curl -s -X POST http://localhost:3000/api/v1/introspect -H "content-type: application/json" -d "{\"token\": \"${token}\", \"identity_provider\": \"maskinporten\"}")

echo
echo "JWT:"
echo "${response}" | jq -S .

echo
echo "Validation:"
echo "${validation}" | jq -S .

echo
echo "Performing request with content-type: application/x-www-form-urlencoded"
response=$(curl -s -X POST http://localhost:3000/api/v1/token -d 'target=my-target' -d 'identity_provider=maskinporten' -d 'authorization_details=[{"type":"urn:altinn:systemuser","systemuser_org":{"authority":"iso6523-actorid-upis","ID":"0192:313367002"},"systemuser_id":["33a0911a-5459-456f-bc57-3d37ef9a016c"],"system_id":"974761076_skatt_demo_system"}]')
token=$(echo ${response} | jq -r .access_token)
validation=$(curl -s -X POST http://localhost:3000/api/v1/introspect -H "content-type: application/json" -d "{\"token\": \"${token}\", \"identity_provider\": \"maskinporten\"}")

echo
echo "JWT:"
echo "${response}" | jq -S .

echo
echo "Validation:"
echo "${validation}" | jq -S .
