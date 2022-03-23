VERSION = `cat .VERSION`
DATE = `cat .DATE`

trap: version 
	@echo
	@echo ---------------------------------------
	@echo Please read README before running make.
	@echo ---------------------------------------
	@echo
	@echo make options are :
	@echo
	@echo linux    : Compile on a Linux and compatible OS  
	@echo solaris  : Compile on a Solaris and compatible OS
	@echo bsd      : Compile on BSD and compatible OS
	@echo openbsd  : Compile on OpenBSD and compatible OS
	@echo macos    : Compile on MacOS X, based on the BSD Makefile
	@echo
	@echo HPUX : use linux flag
	@echo


linux:  linuxchoice action
	@cp Makefile.linux Makefile
	@cd lib/unix/; cp Makefile.linux Makefile
	@cd apps/; cp Makefile.linux Makefile  

solaris: solarischoice action
	@cp Makefile.solaris Makefile
	@cd lib/unix/; cp Makefile.solaris Makefile  
	@cd apps/; cp Makefile.solaris Makefile  

bsd:    bsdchoice action
	@cp Makefile.bsd Makefile
	@cd lib/unix/; cp Makefile.bsd Makefile  
	@cd apps/; cp Makefile.bsd Makefile  

openbsd: openbsdchoice action
	@cp Makefile.openbsd Makefile
	@cd lib/unix; cp Makefile.openbsd Makefile
	@cd apps/; cp Makefile.bsd Makefile

macos:	macoschoice action
	@cp Makefile.macos Makefile
	@cd lib/unix/; cp Makefile.macos Makefile
	@cd apps/; cp Makefile.macos Makefile

action:
	@echo
	@echo "---------------"
	@echo "MAKING MAKEFILE" 
	@echo "---------------"
	@echo
	@echo Please now execute make again.
	@echo

linuxchoice:
	@echo linux flag detected.

solarischoice:
	@echo solaris flag detected.

bsdchoice:
	@echo bsd flag detected.

openbsdchoice:
	@echo openbsd flag detected.

macoschoice:
	@echo MacOS flag detected.

version:
	@echo
	@echo "BUGS V$(VERSION), $(DATE),(c) MARTINEZ Sylvain" 
