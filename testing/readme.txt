```modules```
-       Contains source for a LKM (Loadable Kernel Module) that can be used for testing the Tuning Module

-       Run ```make``` in ```modules/tuningMod/```. To  insert the module into the kernel:
        * Run ```sudo insmod tuningModule.ko```
        * Find the line ```tuningModule has been loaded``` in /var/log/kern.log (Ubuntu) and there will
          be a number next to it.  This is the MAJOR number. ```e.g. tuningModule has been loaded 508```
                * Run ```sudo mknod /dev/tuningMod c MAJOR_NUMBER 0``` to create device for LKM
