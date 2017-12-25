#!/usr/bin/env bash
make main_ios
sshpass -p alpine ssh -p 5555 root@localhost "rm main_ios"
sshpass -p alpine scp -P 5555 main_ios root@localhost:main_ios
sshpass -p alpine ssh -p 5555 root@localhost "./main_ios; echo $?"
