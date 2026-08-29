#!/usr/bin/env python3
import sys

def main():
    path = sys.argv[1]
    with open(path) as f:
        text = f.read()
    print(text.strip())

if __name__ == "__main__":
    main()
