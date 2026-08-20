#!/bin/bash
set -e

# Timestamp every line so a slow or hanging step is identifiable from the
# job log alone. Without this the script emits a handful of coarse echoes
# and there is no way to tell which command is taking the time.
PS4='+ [$(date -u +%H:%M:%S)] '
set -x

echo "This is setup-ckan.bash..."

echo "Installing the packages that CKAN requires..."
# azure.archive.ubuntu.com is intermittently unreachable from the runners
# and apt retries it indefinitely: one job sat here for six hours. Fail
# fast and retry the step instead of waiting on a dead mirror.
apt_updated=false
for attempt in 1 2 3; do
    # Tested inside `if` so that a failure does not trip `set -e` before
    # the retry happens.
    if timeout 120 sudo apt-get update; then
        apt_updated=true
        break
    fi
    echo "apt-get update failed or timed out (attempt ${attempt} of 3)"
    sleep 5
done
if [ "$apt_updated" != true ]; then
    echo "apt-get update failed three times, giving up"
    exit 1
fi
timeout 300 sudo apt-get install -y xmlsec1 libxmlsec1-dev

echo "Installing CKAN and its Python dependencies..."
# Wrapped in timeout so a stalled network fetch fails with a clear message
# instead of holding the runner until the six hour job limit.
timeout 300 git clone https://github.com/ckan/ckan
cd ckan
if [ $CKANVERSION == 'master' ]
then
    echo "CKAN version: master"
else
    CKAN_TAG=$(git tag | grep ^ckan-$CKANVERSION | sort --version-sort | tail -n 1)
    git checkout $CKAN_TAG
    echo "CKAN version: ${CKAN_TAG#ckan-}"
fi

# install the recommended version of setuptools
if [ -f requirement-setuptools.txt ]
then
    echo "Updating setuptools..."
    pip install -r requirement-setuptools.txt
fi

if [ $CKANVERSION == '2.7' ]
then
    echo "Installing setuptools"
    pip install setuptools==39.0.1
fi

timeout 600 python setup.py develop
timeout 900 pip install -r requirements.txt
timeout 900 pip install -r dev-requirements.txt
cd -

echo "Creating the PostgreSQL user and database..."
psql -h localhost -U postgres -c "CREATE USER ckan_default WITH PASSWORD 'pass';"
psql -h localhost -U postgres -c 'CREATE DATABASE ckan_test WITH OWNER ckan_default;'

echo "Initialising the database..."
cd ckan
ckan -c test-core.ini db init
cd -

echo "Installing saml2 requirements..."
timeout 900 pip install -r dev-requirements.txt
echo "Installing ckanext-saml2auth..."
timeout 600 pip install -e .

echo "Moving test.ini into a subdir..."
mkdir subdir
mv test.ini subdir

echo "setup-ckan.bash is done."
