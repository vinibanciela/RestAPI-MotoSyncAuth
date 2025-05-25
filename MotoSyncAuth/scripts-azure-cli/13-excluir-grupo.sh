#!/bin/bash

# Exclui o grupo de recursos e todos os recursos dentro dele
az group delete \
--name grupo-devops \
--yes \
--no-wait
