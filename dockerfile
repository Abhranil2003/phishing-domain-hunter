# Use the official Python image as a base
FROM python:3.9-slim

# Update package list and install necessary packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    tesseract-ocr \
    python3-pil && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the Python script and requirements file into the container
COPY domainhunter.py .
COPY requirements.txt .

# Install the required Python packages
RUN pip install --no-cache-dir -r requirements.txt 

# Define the command to run the application
ENTRYPOINT ["python3", "domainhunter.py"]
