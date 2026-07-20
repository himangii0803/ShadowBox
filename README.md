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

## Run

```bash
g++ -std=c++17 backend/main.cpp -o shadowbox
./shadowbox