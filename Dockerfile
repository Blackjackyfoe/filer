FROM python:3.11.9-alpine3.20@sha256:f9ce6fe33d9a5499e35c976df16d24ae80f6ef0a28be5433140236c2ca482686

WORKDIR /usr/src/app

RUN apk add --no-cache \
      file-dev \
      gcc \
      musl-dev \
      python3-dev \
      libmagic


COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "fastapi", "run", "main.py" ]
