FROM python:3

WORKDIR /usr/src/app

RUN apt-get update \
    && pip install -U pip

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app.py"]