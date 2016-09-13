# LoginDoc

Personal document management

## TODO

- [x] Add document
- [x] Remove document
- [ ] Drag and Drop (FIXME)
- [x] List new document layout
- [x] Upload document for zip file
- [x] Improve Layout and Management
- [x] Improve Security
- [x] Server Configuration

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

### Contributors

Furkan Kalkan