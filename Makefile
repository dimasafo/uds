CFLAGS=-ggdb
TARGET=myweb
PREFIX=/usr/local
WEBROOT=/home/sysadmin/mdi_git/myweb_latest/webroot
XINETD=/etc/xinetd.d
LOGDIR=/home/sysadmin/mdi_git/myweb_latest/log

.PHONY: all clean install uninstall coreon

all: $(TARGET)

myweb: myweb.c
	cc $(CFLAGS) $^ -o $@

clean:
	-rm -f $(TARGET) access.log

install:
	install $(TARGET) $(PREFIX)/bin
	install $(TARGET)-wrap $(PREFIX)/bin
	[ -d $(WEBROOT) ] || mkdir $(WEBROOT)
	#install webroot/* $(WEBROOT)
	install $(TARGET)-xinetd $(XINETD) 
	[ -d $(LOGDIR) ] || mkdir $(LOGDIR)

uninstall:
	rm -f $(PREFIX)/bin/$(TARGET)
	-rm -rf $(WEBROOT)
	rm -rf $(XINETD)/$(TARGET)-xinetd

coreon:
	sysctl kernel.core_pattern=core

