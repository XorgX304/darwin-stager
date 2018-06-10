#!/bin/bash

rsync -azPr -e "ssh -p 2222" --delete . localhost:rsync/stager/
ssh -p2222 localhost "bash -l -c 'cd rsync/stager/ && make' && echo Done!"
rsync -azr -e "ssh -p 2222" localhost:rsync/stager/ .

ssh -p2222 localhost "bash -l -c 'cd rsync/stager/ && ./run.sh' && echo Ran!"

