#!/bin/bash

rsync -azPr -e "ssh -p 2222" --delete . localhost:rsync/stager/
ssh -p2222 localhost "bash -l -c 'cd rsync/stager/ && make main_ios32' && echo Done!"
rsync -azr -e "ssh -p 2222" localhost:rsync/stager/ .

#ssh -p2222 localhost "bash -l -c 'cd rsync/stager/ && ./run.sh' && echo Ran!"
IP=192.168.3.187
ssh root@$IP "rm main"
scp main_ios32 root@$IP:main
ssh root@$IP "./main && echo Ran!"

