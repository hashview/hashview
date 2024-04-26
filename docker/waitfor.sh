#!/bin/sh
# wait-for-mysql.sh

set -e

host="$1"
shift
cmd="$@"

until nc -z "$host" 3306; do
  >&2 echo "MySQL is unavailable - sleeping"
  sleep 1
done

# Run database migrations
echo "Running database migrations..."
export FLASK_APP=hashview.py; flask db upgrade

>&2 echo "MySQL is up - executing command"
exec $cmd