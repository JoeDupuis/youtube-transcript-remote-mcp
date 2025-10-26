#!/bin/bash

# Deployment script for YouTube Transcript MCP
# This script builds and redeploys the application in one shot

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting deployment...${NC}"

# Step 1: Build the Docker image
echo -e "\n${YELLOW}Step 1: Building Docker image...${NC}"
docker compose build

# Step 2: Stop and remove existing containers
echo -e "\n${YELLOW}Step 2: Stopping existing containers...${NC}"
docker compose down

# Step 3: Start the containers
echo -e "\n${YELLOW}Step 3: Starting containers...${NC}"
docker compose up -d

# Step 4: Show status
echo -e "\n${GREEN}Deployment complete!${NC}"
echo -e "\n${YELLOW}Container status:${NC}"
docker compose ps

# Optional: Show logs
echo -e "\n${YELLOW}Recent logs:${NC}"
docker compose logs --tail=20

echo -e "\n${GREEN}✓ Deployment successful!${NC}"
echo -e "Run 'docker compose logs -f' to follow logs"
