#!/usr/bin/env bash
set -e

# 0) Decide desired profile from CLI arg (default: prod)
PROFILE_ARG="${1:-prod}"   # usage: ./bootRun-with-env.sh dev

ENV_FILE=".env.${PROFILE_ARG}"

# 1) Load variables from .env.dev / .env.prod if it exists
if [ -f "${ENV_FILE}" ]; then
  set -a
  . "${ENV_FILE}"
  set +a
  echo "[bootRun-with-env] Loaded environment from ${ENV_FILE}"
else
  echo "[bootRun-with-env] WARNING: ${ENV_FILE} not found, using current environment"
fi

# 2) Show quick DB summary for debugging
echo "[bootRun-with-env] Using DB:"
echo "  DB_HOST=${DB_HOST}"
echo "  DB_PORT=${DB_PORT}"
echo "  DB_NAME=${DB_NAME}"
echo "  DB_USERNAME=${DB_USERNAME}"

# 3) Decide final Spring profile:
#    - if SPRING_PROFILES_ACTIVE is set in env → use it
#    - otherwise use the CLI arg (dev/prod)
PROFILE="${SPRING_PROFILES_ACTIVE:-${PROFILE_ARG}}"
echo "[bootRun-with-env] Running with profile: ${PROFILE}"

# 4) Run Spring Boot with the chosen profile
./gradlew bootRun --args="--spring.profiles.active=${PROFILE}"
