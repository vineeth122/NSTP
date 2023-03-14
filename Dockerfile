FROM python:3.9

COPY src/demo.py src/nstp_pb2.py src/nstp.proto src/requirements.txt /


RUN apt-get update --fix-missing && apt-get -y install gcc


RUN  pip install -r requirements.txt

ENTRYPOINT ["python3","demo.py"]
