#!/bin/sh
# Daily backup. Schedule with cron: 0 22 * * * /path/to/backup.sh
# Copy the backups folder to Google Drive or another machine too.
set -e
mkdir -p backups
pg_dump "$DATABASE_URL" | gzip > "backups/shopbooks-$(date +%F).sql.gz"
find backups -name 'shopbooks-*.sql.gz' -mtime +30 -delete
