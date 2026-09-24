# The update host for installed copies of Tiamat: Caddy, serving the files
# under site/ exactly as they are committed. What the client does with them,
# and why any static host will do, is in the engine repository's
# docs/hosting.md; README.md here has the day-to-day.
FROM caddy:2-alpine
COPY Caddyfile /etc/caddy/Caddyfile
COPY site /srv
