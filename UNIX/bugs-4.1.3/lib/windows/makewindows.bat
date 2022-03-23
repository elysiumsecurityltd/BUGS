@echo Creating Library source to Use with Borland C++ Builder
@echo I just compile all the lib .c files into one big .c file called bugs_win.c
@echo This is an ugly way ! 
@echo But I can't make Builder to compile a library from many source files
type ..\unix\main.c > bugs_win.c
type ..\unix\seed.c >> bugs_win.c
type ..\unix\shuffle.c >> bugs_win.c
type ..\unix\utils.c >> bugs_win.c
type ..\unix\misc.c >> bugs_win.c
type ..\unix\wrapper.c >> bugs_win.c
@echo done.

