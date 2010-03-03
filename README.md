To Build
========

    ./configure --add-module=<this directory>

For some reason this wouldn't compile in Mac OS X (the libmemcached library
uses the bool type which is inexplicably undefined in OS X).

