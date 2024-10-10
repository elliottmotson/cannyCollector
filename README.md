# cannyCollector - A bootleg openCanary correlator

## Prerequisites

- Python 3.x installed on your system.
- `pip` (Python package manager) installed.
- A valid Microsoft Exchange (Office 365) email account.

## Installation

### Create and enter virtual environment 

python3 -m venv venv

Linux

. ./venv/bin/activate

Windows

.\venv\Scripts\Activate.ps1

### Install dependencies

pip install -r requirements.txt

### Listen for agent logs

python3 cannyCollector.py