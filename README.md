# Sooper-EDR-XDR

A prototype of an EDR/XDR system. Developed in Python 3.8. Designed to work on Linux family of systems.

### Description

A students' project written for Cyberforensics subject, migrated over from GitLab to GitHub. The software has capability to:

- scan given json, xml, evtx or plaintext file if it logged any suspicious activity
- convert evtx files to xml format
- dump contents of pcap files into plaintext
- grep key phrases in plaintext files
- send commands to Remote Agent for execution
- scan given evtx file using SIGMA rulesets (uses Zircolite: https://github.com/wagga40/Zircolite)

The repository is split into 3 subapplications: the main app (*Central*), the remote agent to perform actions on a host (*RemoteAgent*) and remote logger (*RemoteLogger*). For Central to gain full functionality, you need to run both Remote apps (servers). The RemoteAgent requires sudo privileges.

### Usage

*python main.py [OPTIONS] COMMAND [ARGS]...*

The software was developed using *Click* library. For further instructions, you can use *--help* flag to show available commands, as well as pair it with specific commands to see more details eg. *python main.py dumpevtx --help*.

### Authors

- Dumin Konrad (owner)
- Koślacz Maria (https://github.com/koslaczmaria)

