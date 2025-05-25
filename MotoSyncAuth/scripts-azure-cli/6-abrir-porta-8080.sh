#!/bin/bash
az vm open-port \
  --resource-group grupo-devops \
  --name vm-devops \
  --port 8080 \
  --priority 901
