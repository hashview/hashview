FROM python:3.9-slim
ENV PIP_NO_CACHE_DIR=off

COPY . /app/
COPY hashview/config.conf.example /app/hashview/config.conf
WORKDIR /app/

RUN python3 -m pip install -r requirements.txt
ENTRYPOINT [ "python3","/app/hashview.py"]
