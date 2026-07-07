#!/usr/bin/env bash
# Creates the edr-events-* index pattern in OpenSearch Dashboards via the
# saved objects API, so "show all processes spawned by bash on host X" can be
# answered from Discover without clicking through the index pattern wizard.
#
# There's no static config file for this the way there is for the OpenSearch
# index template (deploy/opensearch/event-index-template.json) - Dashboards
# saved objects only exist at runtime, so this is a one-time API call instead.
set -euo pipefail

DASHBOARDS_URL="${DASHBOARDS_URL:-http://localhost:5601}"

curl -s -X POST "$DASHBOARDS_URL/api/saved_objects/index-pattern/edr-events?overwrite=true" \
  -H "osd-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
        "attributes": {
          "title": "edr-events-*",
          "timeFieldName": "time"
        }
      }'
echo
echo "Index pattern 'edr-events-*' created. Open Dashboards -> Discover to query it."
