#!/bin/sh
openssl req -x509 -newkey rsa:4096 -nodes -out ./hashview/ssl/cert.pem -keyout ./hashview/ssl/key.pem -days 365