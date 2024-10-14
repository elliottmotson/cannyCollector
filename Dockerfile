FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY cannyCollector.py .

ENV SENDER_EMAIL=''
ENV RECEIVER_EMAIL=''
ENV EMAIL_SUBJECT=''
ENV SMTP_SERVER=''
ENV SMTP_PORT=''
ENV SMTP_USERNAME=''
ENV SMTP_PASSWORD=''

VOLUME /app/data

# Port
EXPOSE 5000

# Exec
CMD ["python", "cannyCollector.py"]
