# cannyCollector - A bootleg openCanary correlator

## Prerequisites

- Python 3.x installed on your system.
- `pip` (Python package manager) installed.
- A valid Microsoft Exchange (Office 365) email account.

## Installation

### Create and enter virtual environment 
```
python3 -m venv venv
```
Linux
```
. ./venv/bin/activate
```
Windows
```
.\venv\Scripts\Activate.ps1
```
### Install dependencies
```
pip install -r requirements.txt
```
### Listen for agent logs
```
python3 cannyCollector.py
```

## Docker 
```
docker build -t cannycollector .
```
### Run

```
docker run -d \
  --name cannycollector \
  -e SENDER_EMAIL='Email' \
  -e RECEIVER_EMAIL='Password' \
  -e EMAIL_SUBJECT='Subject' \
  -e SMTP_SERVER='smtp.server.com' \
  -e SMTP_PORT='587' \
  -e SMTP_USERNAME='Username' \
  -e SMTP_PASSWORD='Password' \
  -p 5000:5000 \
  cannycollector
```