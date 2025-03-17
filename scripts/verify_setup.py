#!/usr/bin/env python3
# Run python3 scripts/verify_setup.py
import atheris
import sys

def test_one_input(data):
    if len(data) > 0 and data[0] == ord('b'):
        print("Found 'b'!")
    
    # Simple string operation
    try:
        s = data.decode("utf-8")
        if "crash" in s:
            raise ValueError("Crash found")
    except:
        pass

atheris.Setup(sys.argv, test_one_input)
atheris.Fuzz()
