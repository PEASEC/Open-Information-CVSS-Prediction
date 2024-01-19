# alpine with py3.8 - reqd version of python for pipenv
FROM python:3.8

# create a directory to run the app in
WORKDIR /app

# install pip system-wide
#RUN pip install pipenv
#RUN apk add --no-cache --virtual .build gcc libc-dev libxml2-dev libxslt-dev
#RUN apk add --no-cache libxml2 libxslt
#RUN pip3 install trafilatura
#RUN apk del .build

# RUN apk add gcc

#move the files into /app
COPY Pipfile.lock /app
COPY Pipfile /app

# add the application files
COPY main.py /app
COPY mongo_handler.py /app
COPY selenium_scraper.py /app

# run the application at launch
RUN pip install pymongo
RUN pip install selenium
ENTRYPOINT ["pipenv", "run", "python3", "main.py"]