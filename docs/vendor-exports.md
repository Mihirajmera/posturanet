# Getting Wiz, Orca and Prisma Cloud findings as JSON

PosturaNet reads findings from Wiz, Orca and Prisma Cloud as **JSON from their APIs**. It
refuses CSV exports: none of the three vendors documents its CSV columns, and PosturaNet doesn't
guess which column holds the resource or the rule.

Each command below writes a file you can pass straight to PosturaNet:

```bash
posturanet findings list wiz.json --all
posturanet fix wiz.json
```

The requests are the ones cited in `src/posturanet/ingest/vendors.py`, from each vendor's public
API documentation or published integration code. They only read. Keep the output files out of
git: they name your accounts and resources.

## Prisma Cloud

Uses [List Alerts V2](https://pan.dev/prisma-cloud/api/cspm/get-alerts-v-2/). `detailed=true`
is needed: it adds the compliance metadata PosturaNet uses to map a policy to a control. Use your
tenant's API host (`api.prismacloud.io`, `api2.prismacloud.io`, `api.eu.prismacloud.io`, ...)
and an access key with read permission.

```bash
PRISMA=https://api.prismacloud.io
TOKEN=$(curl -s -X POST "$PRISMA/login" -H "Content-Type: application/json" \
  -d "{\"username\": \"$PRISMA_ACCESS_KEY\", \"password\": \"$PRISMA_SECRET_KEY\"}" \
  | python -c "import json, sys; print(json.load(sys.stdin)['token'])")
curl -s "$PRISMA/v2/alert?detailed=true&alert.status=open&timeType=relative&timeAmount=30&timeUnit=day&limit=10000" \
  -H "x-redlock-auth: $TOKEN" > prisma.json
```

## Orca

Uses the serving-layer alert query. `ORCA` is the address you sign in at (for example
`https://app.eu.orcasecurity.io`); the token is an Orca API token with read access.

```bash
ORCA=https://app.eu.orcasecurity.io
curl -s -X POST "$ORCA/api/serving-layer/query" \
  -H "Authorization: Token $ORCA_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"query": {"models": ["Alert"], "type": "object_set"}, "limit": 1000, "start_at_index": 0}' \
  > orca.json
```

Orca alerts carry no control ids. Map the alert types you want fixed in `.posturanet.yml`
under `detectors.orca.rules`; the rest end with the outcome `none` and that reason.

## Wiz

Uses the `issuesV2` GraphQL query with a service account (client id and secret, scope
`read:issues`). `WIZ_API` is your tenant's GraphQL endpoint, shown under **User Settings →
Tenant** (for example `https://api.us17.app.wiz.io/graphql`). Accounts on the Wiz for Gov
tenant sign in at `auth.gov.wiz.io` instead.

```bash
WIZ_API=https://api.us17.app.wiz.io/graphql
TOKEN=$(curl -s -X POST https://auth.app.wiz.io/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode grant_type=client_credentials --data-urlencode audience=wiz-api \
  --data-urlencode "client_id=$WIZ_CLIENT_ID" --data-urlencode "client_secret=$WIZ_CLIENT_SECRET" \
  | python -c "import json, sys; print(json.load(sys.stdin)['access_token'])")
cat > wiz-query.json <<'EOF'
{"query": "query($first: Int, $after: String) { issues: issuesV2(first: $first, after: $after, filterBy: {status: [OPEN, IN_PROGRESS]}) { nodes { id status severity createdAt sourceRule { __typename ... on Control { id name securitySubCategories { title category { name framework { name } } } } ... on CloudConfigurationRule { id name } ... on CloudEventRule { id name } } entitySnapshot { id type nativeType name providerId externalId region subscriptionExternalId } } pageInfo { hasNextPage endCursor } } }", "variables": {"first": 500}}
EOF
curl -s -X POST "$WIZ_API" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @wiz-query.json > wiz.json
```

If `pageInfo.hasNextPage` is `true` in `wiz.json`, run the last command again with
`"after": "<endCursor>"` added to `variables`, into another file, and pass both files.

## Still have a CSV?

Open an issue with the CSV's header row only (no data rows). If enough people need one
vendor's CSV, PosturaNet will read it, and refuse any file missing a column it relies on.
