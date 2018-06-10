#!/bin/bash

sshpass -p alpine ssh -p3333 root@localhost "rm main_ios"
sshpass -p alpine scp -P3333 main_ios root@localhost:main_ios
sshpass -p alpine ssh -p3333 root@localhost "./main_ios && echo Exit!"

