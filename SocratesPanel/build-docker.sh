#!/bin/bash
docker rm -f socrates_panel
docker build -t socrates_panel .
docker run --name=socrates_panel --rm -p 1337:1337 -it socrates_panel