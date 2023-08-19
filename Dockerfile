# syntax=docker/dockerfile:1
FROM python:3.8-alpine
WORKDIR /
ENV FLASK_APP=hashview
ENV FLASK_RUN_HOST=0.0.0.0
RUN apk add --no-cache gcc musl-dev linux-headers libffi-dev
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
EXPOSE 5000
COPY . .
CMD ["flask", "run"]