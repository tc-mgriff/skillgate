# SkillGate web app image.
FROM python:3.12-slim

# non-root user
RUN useradd --create-home --uid 10001 skillgate

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Cisco scanner is OPTIONAL. Uncomment to bake it into the image so the
# cisco engine activates automatically. It pulls a fair number of deps.
# RUN pip install --no-cache-dir cisco-ai-skill-scanner

COPY app ./app
COPY scanner ./scanner

USER skillgate
EXPOSE 8000
# uvicorn with a small worker count; put a real ASGI process manager in front
# for production.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
