all: gotee

gotee:
	@sh clean.sh
	@sh compile.sh
	@sh install.sh


.PHONY: clean

clean:
	@sh clean.sh
	@rm -f _run.sh

