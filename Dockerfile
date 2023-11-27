# Use an official Python runtime as a parent image
FROM python:3.10

# Set the working directory in the container
WORKDIR /usr/src/app

# Install any needed packages specified in requirements.txt
RUN pip install pyyaml

# Copy the required files into the container at /usr/src/app
COPY polardns.py .
COPY polardns.yml .

# Make port 53 available to the world outside this container
EXPOSE 53/udp 53/tcp

# Run polardns.py when the container launches
CMD ["python", "polardns.py"]
