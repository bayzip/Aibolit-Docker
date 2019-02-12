# Aibolit-Docker
Scan your file using Aibolit in Docker

## Aibolit
Aibolit is one of free malware scanner with unique heuristic analysis. 

## Environment
From Default our image will scan directory "/usr/share/nginx/html", if you want to change directory simple running docker with following command

```
--env  MYWEB {YOUR_DIRECTORY}
or
-e MYWEB {YOUR_DIRECTORY}
```

## Using with Docker
If you want to run Docker Aibolit please make sure to limit CPU usage!

Sample Running with Singgle Container
```
docker run -d -it --cpus=".5" -v /var/lib/docker/volumes/wp_data/_data/:/usr/share/nginx/html modinbah/aibolit:latest
```

Sample Running with Docker Stack
```
version: "3"
services:
  aibolit:
    image: modinbah/aibolit:latest
    deploy:
      replicas: 1
      update_config:
        parallelism: 2
        delay: 10s
      restart_policy:
        condition: on-failure
      resources:
        limits:
          cpus: '1.0'
          memory: 1024M
    volumes:
      - wp_data:/usr/share/nginx/html
      
volumes:
  wp_data:
    external: true
```
