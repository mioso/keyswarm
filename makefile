test:
	py.test
dist:
	rm -rf dist/
	pyside2-rcc resources.qrc -o keyswarm/resources.py
	pyinstaller main.spec
dist-single:
	rm -rf dist/
	pyside2-rcc resources.qrc -o keyswarm/resources.py
	pyinstaller main-single.spec
install:
	pyside2-rcc resources.qrc -o keyswarm/resources.py
