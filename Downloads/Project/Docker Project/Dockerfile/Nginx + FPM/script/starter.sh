#!/bin/bash

# Optimization Configuration Based on CPU Core
procs=$(cat /proc/cpuinfo | grep processor | wc -l)
sed -i -e "s/worker_processes auto/worker_processes $procs/" /etc/nginx/nginx.conf
chown -R nginx:nginx /usr/share/nginx/html

/usr/bin/supervisord -n -c /etc/supervisord.conf
