if [[ -n "$(python -mplatform | grep debian-7)" ]]; then
    pip install -r pyinstaller-requirements-debian7.txt
else
    pip install -r pyinstaller-requirements.txt
fi
