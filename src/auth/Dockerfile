FROM python:3.9

COPY auth/requirements.txt requirements.txt
RUN python3 -m pip install --upgrade pip && python3 -m pip install -r requirements.txt

COPY auth auth

RUN chmod +x auth/main.py
RUN chmod +x auth/run.sh


ENTRYPOINT [ "python3", "auth/main.py" ]