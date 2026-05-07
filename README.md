# Log Analysis & Threat Detection System

A Python-based cybersecurity tool designed to analyze authentication logs and detect suspicious activities such as brute-force attacks and potential account compromise.

## Features

* Detects failed login attempts from log files
* Identifies brute-force attacks using configurable thresholds
* Classifies suspicious activity into LOW, MEDIUM, and HIGH severity levels
* Detects potential account compromise (successful login after multiple failures)
* Generates structured security reports

## Tech Stack

* Python
* Regular Expressions (Regex)
* File Handling

## How to Run

Run the script:
python log_analysis.py

Then provide:

* Log file name
* Threshold value
* Report generation option

## Use Case

Simulates how Security Operations Center (SOC) analysts monitor logs to:

* Detect attack patterns
* Identify malicious IPs
* Analyze login behavior

## Future Improvements

* Real-time log monitoring
* Visualization dashboard
* Integration with SIEM tools

