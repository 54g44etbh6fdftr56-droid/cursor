#!/bin/bash

# Wait for the Redis server to start
sleep 5

redis-cli SET FLAG $(cat /flag.txt)

rm /flag.txt