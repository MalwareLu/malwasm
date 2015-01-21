```                  _                             
  _ __ ___   __ _| |_      ____ _ ___ _ __ ___  
 | '_ ` _ \ / _` | \ \ /\ / / _` / __| '_ ` _ \ 
 | | | | | | (_| | |\ V  V / (_| \__ \ | | | | |
 |_| |_| |_|\__,_|_| \_/\_/ \__,_|___/_| |_| |_|
```

# Folders
* `conf/malwasm.conf` - is the configuration file for malwasm
* `core/` - contains malwasm python lib
* `cuckoo/` - contains the cuckoo package that needs to be copied in your cuckoo install folder
* `doc/` - contains some doc
* `pin/` - contains the malwpin dll source code and makefile
* `utils/` - contains scripts to run analysis and data insertion
	* `create_db.py` - script to force the creation of the database (usefull to reset the db)
	* `file2db.py` - script to insert sample data into the db
	* `db2file.py` - script to extract sample data from the db
	* `submit.py` - all in one script, to submit sample to cuckoo and insert data into malwasm db
* `web/` - contains the webservice python script
	* `malwasm_web.py` - the webservice listening on http://127.0.0.1:5000

# Installation
## Dependencies
* python2.7 
* python-psycopg2
* python-argparse
* python-flask
* python-progressbar
* cuckoo
* postgresql
* pintool

## To install python dependencies
*`sudo apt-get install python-psycopg2 python-flask python-progressbar python-argparse`
or
*`pip install psycopg2 flask progressbar argparse`

## Pintool
Pintool cannot be put directly inside malwasm due to licence issue. You have to download it by yourself.
* http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.12-53271-msvc10-ia32_intel64-windows.zip

Once downloaded you have to extract all the .dll and .exe files of the subfolder
* `/pin-2.12-53271-msvc10-windows/ia32/bin/`
to the folder:
* `malwasm/cuckoo/analyzer/windows/bin`

## Cuckoo part
* You need to have cuckoo correctly set up
* You have to copy files from `malwasm/cuckoo/analyzer/windows/` into your cuckoo installation in the subfolder `cuckoo/analyzer/windows/`
* Your cuckoo VM needs to have a share folder with write permission on it
* Update cuckoo section of `conf/malwasm.conf` to match your configuration
* Run `cuckoo.py`

## Database
* Run your postgresql database
* The current config in `conf/malwasm.conf` works with an out of box config of postgresql
* WARNING: if you want to use the create_db scripts, you have to use the default postgres account otherwise you can use the schema available in `conf/schema.sql`

## Run analysis
* You can directly run a sample analysis with `utils/submit.py`
```
# standard analysis of the a binary
utils/submit.py malware/r.exe

# only start record instruction when it pass on adr-start and stop on adr-stop
utils/submit.py --options adr-start=0x401290,adr-stop=0x401384 malware/r.exe
```

* If data insertion into malwasm db failed you can re run the insertion with
```
utils/file2db -d /tmp/data/13508268572/ # where /tmp/data is the share folder

utils/file2db -d /tmp/data/13508268572/  --pin-param foo # where /tmp/data is the share folder
```

* If you want to clean the database you can use
```
utils/create_db.py --force
```

* PS: data insertion can take some serious time, so just be patient!

## Webservice

* To see the report you have to run the webservice
```
web/malwasm_web.py
```

* Go to http://127.0.0.1:5000 and select your sample
