# Pure-Python stub mail server image for the E2E suite (M06-T01).
#
# No Node.js and no upstream code: a minimal asyncio IMAP4rev1 server
# (server.py, LOGINA/SELECT/LIST/FETCH/NOOP with hardcoded state) plus
# aiosmtpd for SMTP. The gateway's vendored upstream imap-mcp-server child
# connects to this instead of a real mailbox provider, so the E2E suite
# needs no internet access and no real credentials.
FROM python:3.12-slim-bookworm

RUN pip install --no-cache-dir aiosmtpd

COPY server.py /app/server.py
COPY healthcheck.py /app/healthcheck.py

EXPOSE 143 25

CMD ["python", "/app/server.py"]
