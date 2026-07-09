# =============================================================================
# SURU — Tier 4 Frontdoor: nginx reverse proxy
# =============================================================================
# Thin layer over the official nginx alpine image that bakes in apache2-utils
# at BUILD time so the entrypoint can materialise a bcrypt htpasswd file.
#
# Why a build-time install (not `apk add` at container start):
#   The service runs hardened — `user: "101:101"`, `cap_drop: [ALL]` (SEC-030).
#   A non-root container cannot run `apk` (it needs to lock /lib/apk/db), so the
#   previous runtime `apk add apache2-utils` failed with
#   "Unable to lock database: Permission denied" and the container crash-looped.
#   Installing at build time (as root, in the builder) leaves the runtime
#   container non-root and self-contained.
#
# Validate: docker build -t suru-t4-frontdoor-proxy:local .
# =============================================================================
FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

# apache2-utils provides `htpasswd` (bcrypt via -B) used by scripts/entrypoint.sh
# to build /etc/nginx/auth/htpasswd for the frontdoor's HTTP Basic auth.
RUN apk add --no-cache apache2-utils \
 && rm -rf /var/cache/apk/*

# Run non-root by default at the IMAGE level (defense-in-depth; Trivy DS-0002).
# uid/gid 101 is the `nginx` user shipped by the base image and already used by the
# compose service (`user: "101:101"`). The compose override remains authoritative;
# this makes a bare `docker run suru-t4-frontdoor-proxy:local` non-root too, so the
# image is hardened even without the compose layer. Numeric form keeps the check
# unambiguous (no passwd name resolution) and matches compose exactly.
USER 101:101
