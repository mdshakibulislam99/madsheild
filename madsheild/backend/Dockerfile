FROM python:3.13-slim

WORKDIR /srv/madshield
COPY madsheild/backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && useradd --create-home app
COPY --chown=app:app madsheild/backend madsheild/backend
COPY --chown=app:app madsheild/fontend madsheild/fontend

USER app
EXPOSE 8001
CMD ["python", "-m", "uvicorn", "madsheild.backend.main:app", "--host", "0.0.0.0", "--port", "8001"]
