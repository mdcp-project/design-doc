FROM python:3.9

COPY auth auth
RUN python3 -m pip install --upgrade pip && python3 -m pip install -r auth/requirements.txt


RUN chmod +x auth/main.py
RUN chmod +x auth/run.sh


ENTRYPOINT [ "python3", "auth/main.py" ]