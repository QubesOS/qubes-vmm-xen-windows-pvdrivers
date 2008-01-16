This is my GPL'd Xen HVM PV drivers for Windows. You can contact me at 
james.harper@bendigoit.com.au, or on the xen-devel mailing list. 

Only block device drivers are supported so far. Also it's probably only 
really useful to anyone who knows something about windows driver 
development. 

My test environment is Xen 3.1.1 (64 bit Hypervisor) and Windows 2003 
sp2 (32 bit PAE). YMMV. 

You can get the source using Mercurial at 
http://xenbits.xensource.com/ext/win-pvdrivers.hg. 

Please do not in any way consider it ready for production use. 
Definitely do not use them on a production DomU. While I have never seen 
them cause a problem with the hypervisor or Dom0, I would also be very 
wary of using them on a production physical machine too. It now seems 
fairly sane in use, I haven't had a crash for a while, but I haven't 
done nearly enough testing yet. 

See BUILDING.txt for instructions on building the drivers. 

See INSTALLING.txt for instructions on installing the drivers. 

See TODO.txt for known problems and future plans. 

