This is my GPL'd Xen HVM PV drivers for Windows. You can contact me at 
james.harper@bendigoit.com.au, or on the xen-devel mailing list. 

Block and Network drivers are supported, and a service is supplied which
will respond to 'xm shutdown' and 'xm reboot' commands.

My test environment is Xen 3.1.1 (64 bit Hypervisor) and Windows 2003 
sp2 (32 bit PAE). YMMV. There have definitely been problems reported on
Intel architectures.

You can get the source using Mercurial at 
http://xenbits.xensource.com/ext/win-pvdrivers.hg. 

Please do not in any way consider it ready for production use. 
Definitely do not use them on a production DomU. While I have never seen 
them cause a problem with the hypervisor or Dom0, I would also be very 
wary of using them on a production physical machine too.

It now seems fairly sane, I'm using it on a few low-risk production
machines without any problems.

See BUILDING.txt for instructions on building the drivers. 

See INSTALLING.txt for instructions on installing the drivers. 

See TODO.txt for known problems and future plans. 

