FROM python:alpine3.12

WORKDIR /app

COPY . /app

RUN apk add gcc libc-dev openssl-dev libffi-dev && \
    pip install -r requirements.txt
    

EXPOSE 80

CMD ["python","app.py"]
