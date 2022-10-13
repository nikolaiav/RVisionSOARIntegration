FROM python:3.7-alpine

COPY requirements.txt /rstcloud/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /rstcloud/requirements.txt

COPY app /rstcloud/app

WORKDIR /rstcloud

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]