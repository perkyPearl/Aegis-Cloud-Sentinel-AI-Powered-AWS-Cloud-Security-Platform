FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY app.py /app/
COPY scanner/ /app/scanner/
COPY dashboard/ /app/dashboard/
COPY reports/ /app/reports/

RUN mkdir -p /app/output

EXPOSE 8000

CMD ["python","app.py"]