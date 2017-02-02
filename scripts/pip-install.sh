_python_version=`python -c 'import sys; version=sys.version_info[:3]; print("{0}.{1}.{2}".format(*version))'`

if [ "$_python_version" == "2.6.6" ]
then
  pip install -r pyinstaller-requirements-2.6.txt
else
  pip install -r pyinstaller-requirements.txt
fi
