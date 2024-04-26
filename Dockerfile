FROM --platform=linux/amd64 python:3.8

WORKDIR /app

# Define build-time environment variables
ARG DB_SERVER
ARG DB_USERNAME
ARG DB_PASSWORD
ARG SMTP_SERVER
ARG SMTP_SENDER_ADDRESS
ARG SMTP_USERNAME
ARG SMTP_PASSWORD
ARG SMTP_TLS
ARG CERT_SUBJECT

# Set build-time environment variables as environment variables
ENV DB_SERVER=${DB_SERVER} \
    DB_USERNAME=${DB_USERNAME} \
    DB_PASSWORD=${DB_PASSWORD} \
    SMTP_SERVER=${SMTP_SERVER} \
    SMTP_SENDER_ADDRESS=${SMTP_SENDER_ADDRESS} \
    SMTP_USERNAME=${SMTP_USERNAME} \
    SMTP_PASSWORD=${SMTP_PASSWORD} \
    SMTP_TLS=${SMTP_TLS} \
    CERT_SUBJECT=${CERT_SUBJECT}
 
COPY . /app

# # Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt 
RUN apt-get update && apt-get install -y netcat-traditional 

# Read ENV from .env file and pass it to the container so setup.py can read it
RUN python3 setup.py


ENTRYPOINT ["sh", "-c", "./waitfor.sh db && python3 hashview.py"]
