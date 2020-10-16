# keyswarm
password manager for security oriented teams 

* cross platform gui client
* gpl licensed
* [pass](https://www.passwordstore.org) compatible

## manual install

```
git clone https://github.com/mioso/keyswarm
cd keyswarm
mkdir venv`
virtualenv -p python3 venv
source venv/bin/activate
pip install -r requirements.txt
make install
```
## build distributable 

### unixoids

```
make dist
```

or to build a single elf file

```
make dist-single
```

### windows

```
build_app.bat
```

or to build a single windows executable

```
build_exe.bat
```
