FROM python:3.13-alpine

ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY banner.py .

USER nobody
EXPOSE 2222
CMD ["python", "banner.py"]
