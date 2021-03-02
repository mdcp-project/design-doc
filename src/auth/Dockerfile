FROM python:3.8.2-alpine

COPY auth auth
RUN python -m pip install -r auth/requirements.txt

RUN chmod +x auth/main.py


ENTRYPOINT [ "auth/main.py" ]