# Step 1: Use an official Python image as a base image
FROM python:3.9-slim

# Step 2: Set the working directory in the container
WORKDIR /app

# Step 3: Copy the current directory contents into the container
COPY . /app

# Step 4: Install dependencies listed in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Expose port 8000 for the FastAPI app to be accessible
EXPOSE 8000

# Step 6: Set an environment variable to prevent Python from buffering stdout/stderr
ENV PYTHONUNBUFFERED=1

# Step 7: Define the command to run your app using uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]