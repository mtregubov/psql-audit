# psql-audit

This project was inspired by https://github.com/cloudproud/psql-proxy

## What is it
A simple go service allowing audit and log psql wire protocol packages being send between the client and server.

## Usage
```bash
$ make build
$ psql-audit -d 127.0.0.1:5432 -l 0.0.0.0:2345
```
Output will be the following
```
{"time":"2024-04-15T16:24:32.390911+03:00","level":"INFO","msg":"psql-audit listening","address":"0.0.0.0:2345"}
{"time":"2024-04-15T16:24:39.421961+03:00","level":"INFO","msg":"incoming connection, dialing PostgreSQL server..."}
{"time":"2024-04-15T16:24:39.4226+03:00","level":"INFO","msg":"starting sniffing the PSQL protocol"}
{"time":"2024-04-15T16:24:39.423477+03:00","level":"INFO","msg":"client to server","version":80877103}
{"time":"2024-04-15T16:24:40.081595+03:00","level":"INFO","msg":"incoming connection, dialing PostgreSQL server..."}
{"time":"2024-04-15T16:24:40.082122+03:00","level":"INFO","msg":"starting sniffing the PSQL protocol"}
{"time":"2024-04-15T16:24:40.0822+03:00","level":"INFO","msg":"client to server","version":80877103}
{"time":"2024-04-15T16:24:59.697073+03:00","level":"INFO","msg":"client to server","ip":"192.168.1.119:49971","app":"psql","user":"qq","type":"Q","msg":"select count(1) from test where 1=1;"}
```
