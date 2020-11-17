FROM python:3

WORKDIR /usr/src/app

COPY requirements.txt .

RUN apt-get update \ 
    && pip install -U pip \
    && pip install --no-cache-dir -r requirements.txt \
    && python -m spacy download en_core_web_sm
COPY . .

CMD ["python", "app.py"]
