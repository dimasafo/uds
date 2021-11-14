CFLAGS=-ggdb
TARGET=myweb

PREFIX=/usr/local
USRLOCAL=/usr/local
WEBROOT=$(CURDIR)/webroot
XINETD=/etc/xinetd.d
LOGDIR=$(CURDIR)/log

.PHONY: all clean install uninstall coreon

all: $(TARGET)

rebuild: clean myweb uninstall install

myweb: myweb.c
	cc $(CFLAGS) $^ -o $@ -lpthread

clean:
	-rm -f $(TARGET) access.log

install:
	install $(TARGET) $(USRLOCAL)/bin
	install $(TARGET)_wrap $(USRLOCAL)/bin
	[ -d $(WEBROOT) ] || mkdir $(WEBROOT)
	#install webroot/* $(WEBROOT)
	ln -s $(CURDIR) $(USRLOCAL)/bin/myweb_folder
	install $(TARGET)-xinetd $(XINETD) 
	[ -d $(LOGDIR) ] || mkdir $(LOGDIR)
	systemctl restart xinetd

uninstall:
	rm -f $(USRLOCAL)/bin/$(TARGET)
	#-rm -rf $(WEBROOT)
	rm -rf $(XINETD)/$(TARGET)-xinetd
	-rm $(USRLOCAL)/bin/myweb_folder
	-rm $(USRLOCAL)/bin/$(TARGET)_wrap

coreon:
	sysctl kernel.core_pattern=core

