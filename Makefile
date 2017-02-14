## -*- Makefile -*-
##
## User: leos
## Time: Feb 14, 2017 10:58:46 AM
## Makefile created by Oracle Developer Studio.
##
## This file is generated automatically.
##


#### Compiler and tool definitions shared by all build targets #####
CC = gcc
BASICOPTS = -g
CFLAGS = $(BASICOPTS)


# Define the target directories.
TARGETDIR_app=bin


all: $(TARGETDIR_app)/app

## Target: app
OBJS_app =  \
	$(TARGETDIR_app)/packet_parser.o
SYSLIBS_app = -lm -lpthread -lpcap
USERLIBS_app = $(SYSLIBS_app) 
DEPLIBS_app =  
LDLIBS_app = $(USERLIBS_app)


# Link or archive
$(TARGETDIR_app)/app: $(TARGETDIR_app) $(OBJS_app) $(DEPLIBS_app)
	$(LINK.c) $(CFLAGS_app) $(CPPFLAGS_app) -o $@ $(OBJS_app) $(LDLIBS_app)


# Compile source files into .o files
$(TARGETDIR_app)/packet_parser.o: $(TARGETDIR_app) packet_parser.c
	$(COMPILE.c) $(CFLAGS_app) $(CPPFLAGS_app) -o $@ packet_parser.c



#### Clean target deletes all generated files ####
clean:
	rm -f \
		$(TARGETDIR_app)/app \
		$(TARGETDIR_app)/packet_parser.o
	rm -f -r $(TARGETDIR_app)


# Create the target directory (if needed)
$(TARGETDIR_app):
	mkdir -p $(TARGETDIR_app)


# Enable dependency checking
.KEEP_STATE:
.KEEP_STATE_FILE:.make.state.GNU-amd64-Linux

