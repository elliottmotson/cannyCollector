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

# GNU General Public License v3.0

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

## License Summary

- You can use, modify, and distribute this software, but you must
  provide the same rights to others.
- You must include a copy of the GPL license with any distribution.
- If you modify the software and distribute it, you must also
  distribute the source code of your modifications.
