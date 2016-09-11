# LoginDoc

Personal document management has been developed to meet the needs, has a simple structure your files copy doc folder and enjoy

Note: Please edit `docs/index.html` and edit list


## Requirements

```
sudo apt install build-essential python-dev python3-pip python-pip
pip3 install -t lib -r requirements.txt
```

## Usage

```
git clone https://github.com/MertcanGokgoz/LoginDoc.git
cd LoginDoc
uwsgi --socket 127.0.0.1:3031 --wsgi-file wsgi.py --callable application --processes 4 --threads 2 --stats 127.0.0.1:9191
```

## LICENSE

[MIT](https://github.com/MertcanGokgoz/LoginDoc/blob/master/LICENSE)