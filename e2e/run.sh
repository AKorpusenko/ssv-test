#!/bin/bash

# Step 1: Start the beacon_proxy and ssv-node services
docker compose up -d --build beacon_proxy ssv-node-1 ssv-node-2 ssv-node-3 ssv-node-4

# Step 2: Run logs_catcher in Mode Slashing
docker compose run --build logs_catcher logs-catcher --mode Slashing

# Step 3: Stop the services
docker compose down

# Step 4. Run share_update for non leader
docker compose run --build share_update share-update

# Step 6: Start the beacon_proxy and ssv-nodes again
docker compose up -d beacon_proxy ssv-node-1 ssv-node-2 ssv-node-3 ssv-node-4

# Step 7: Run logs_catcher in Mode BlsVerification for non leader
docker compose run --build logs_catcher logs-catcher --mode BlsVerification
