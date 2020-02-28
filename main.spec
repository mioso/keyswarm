# -*- mode: python -*-

from PyInstaller.utils.hooks import collect_data_files

#x = collect_data_files('xxx')
xx = []
#counter = 0
#for k, v in x:
#	if counter == 0:
#		xx.append((k, '.'))
#		counter += 1
#	else:
#		try:
#			xx.append((k, v.split('xxx\\')[1]))
#		except:
#			xx.append((k, v.split('xxx/')[1]))

added_files = xx
extra_imports = []

block_cipher = None

a = Analysis(['kswarm'],
             pathex=['C:\\Users\\user\\keyswarm'],
	     binaries=[],
	     datas=added_files,
	     hiddenimports=extra_imports,
	     hookspath=[],
	     excludes=[],
	     win_no_prefer_redirects=False,
	     win_private_assemblies=False,
	     cipher=block_cipher,
	     noarchive=False)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(pyz,
	  a.scripts,
	  a.binaries,
	  a.zipfiles,
	  a.datas,
	  [],
	  name='keyswarm',
	  debug=True,
	  bootloader_ignore_signals=False,
	  strip=False,
	  upx=True,
	  runtime_tmpdir=None,
	  console=True)
