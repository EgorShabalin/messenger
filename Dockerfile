FROM python:3.10

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ENV TZ=Europe/Istanbul
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /code
RUN pip install --upgrade pip

COPY server.py server.py
COPY docker-compose.yml docker-compose.yml
COPY Dockerfile Dockerfile
COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt