#!/bin/bash
az vm open-port \
  --resource-group grupo-devops \
  --name vm-devops \
  --port 22 \
  --priority 900
