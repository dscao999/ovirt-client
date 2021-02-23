#!/bin/bash
curl --location --data "grant_type=password&scope=ovirt-app-api&username=test1@internal&password=Lenovo@123" \
	--header "Accept: application/json" https://engine.cluster//ovirt-engine/sso/oauth/token
