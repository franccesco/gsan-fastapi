# Use the official Python base image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file to the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code to the container
COPY . .

# Expose the port that the FastAPI server will listen on
EXPOSE 8000

# Start the FastAPI server
CMD ["gunicorn", "gsan.main:app", "--worker-class", "uvicorn.workers.UvicornWorker", "-c", "gunicorn_conf.py", "-w", "4", "-b", "0.0.0.0:8000"]
