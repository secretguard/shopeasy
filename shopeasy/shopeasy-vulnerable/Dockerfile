FROM python:3.11-slim
LABEL description="ShopEasy Vulnerable — API Security Lab"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
