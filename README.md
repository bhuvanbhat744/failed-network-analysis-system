# NETRA – Network Intelligence & Threat Detection System

## About the Project

NETRA is a project we started with the aim of building a network monitoring and threat detection system.

The idea was simple: monitor multiple machines connected to a network, identify suspicious activities, detect possible attacks, and show everything on a dashboard.

I wanted to explore how network attacks actually happen and try building something that could identify them instead of just learning about them theoretically.

## What I Wanted to Detect

I wanted NETRA to detect and alert us about:

- **Brute-force attacks:** Repeated attempts to guess passwords and gain access to a system.
- **Port scanning:** Attempts to find open ports on a machine.
- **Network scanning:** Attempts to discover other devices on a network.
- **Suspicious network traffic:** Unusual communication between machines.
- **Failed login attempts:** Repeated unsuccessful login attempts.

## What I Tried to Build

I planned a small testing environment using three machines:

- One machine to monitor the network and run the dashboard.
- One machine to simulate attacks.
- One machine to act as the target.

I wanted to capture network traffic, collect system logs, analyse suspicious activities, and display the results through a Streamlit dashboard.

## What I Used

- Python
- Streamlit
- Scapy
- SQLite
- Nmap
- Hydra
- Wireshark
- TCPDump
- Rsyslog
- Kali Linux

## What I Managed to Do

I managed to set up the three-machine environment and establish communication between the machines.

I experimented with network traffic capture, log forwarding, authentication monitoring, and attack simulations. I also developed a basic Streamlit dashboard to display security events.

## What Went Wrong

Honestly, I couldn't complete NETRA the way I had originally imagined.

I wanted to build a system that could reliably detect different types of attacks and automatically generate alerts. Although I managed to set up the environment and get some individual components working, I struggled to bring everything together into a complete and reliable detection system.

There were many things I couldn't figure out, and several things didn't work as expected.

I wouldn't call NETRA a successful implementation of what I originally planned. But I did get to work with real machines, experiment with cybersecurity tools, understand network traffic, and learn how different parts of a monitoring system fit together.

**I started this project hoping to build something much bigger. I couldn't achieve everything, but this is what I tried, what I managed to build, and what I learned along the way.**
