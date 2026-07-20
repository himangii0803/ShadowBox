# ShadowBox

ShadowBox is a C++-based Malware Behavior Analysis Sandbox that visualizes API-call sequences from the NASA/ACM malware behavior dataset.

## Features

- Malware behavior investigation
- SHA256 hash search
- Random malware case selection
- Interactive evidence board
- Risk score visualization
- Behaviour replay timeline
- Digital forensic terminal
- Investigation report generation
- Export investigation report as PDF

## Tech Stack

- C++
- HTML
- CSS
- JavaScript
- GitHub

## Project Structure

backend/
frontend/
dataset/


##  Live Demo

**Open ShadowBox:**  
https://potential-goldfish-r4w94p47vpggh575v-8080.app.github.dev/

> Note: This demo is hosted using GitHub Codespaces. If the Codespace is stopped, the application will be temporarily unavailable.

## Run

```bash
g++ -std=c++17 backend/main.cpp -o shadowbox
./shadowbox
