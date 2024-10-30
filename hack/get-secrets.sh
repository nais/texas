#!/bin/bash

if [ -f ".env" ] ; then
    rm ".env"
fi

kubectl get secret $(kubectl get azureapp texas-client --template='{{.spec.secretName}}') -o json | jq -r '.data | map_values(@base64d) | keys[] as $k | "\($k)=\(.[$k])"' >> .env
kubectl get secret $(kubectl get jwker texas-client --template='{{.spec.secretName}}') -o json | jq -r '.data | map_values(@base64d) | keys[] as $k | "\($k)=\(.[$k])"' >> .env
kubectl get secret $(kubectl get maskinportenclient texas-client --template='{{.spec.secretName}}') -o json | jq -r '.data | map_values(@base64d) | keys[] as $k | "\($k)=\(.[$k])"' >> .env
