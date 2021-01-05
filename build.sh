#!/bin/bash
rm dist/*
python3 setup.py bdist_wheel sdist
python setup.py bdist_wheel
