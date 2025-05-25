#!/bin/bash
az vm create \
  --resource-group grupo-devops \
  --name vm-devops \
  --image Ubuntu2204 \
  --size Standard_B1s \
  --admin-username azureuser \
  --authentication-type password \
  --admin-password '@VmDevOps#2025!' \
  --location brazilsouth
