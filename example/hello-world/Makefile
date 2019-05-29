all: comp

comp:
	$(shell GOPATH=${GOPATH}:`pwd` gotee build src/main.go)
	@echo "Done compiling"

.PHONY: run

run:
	GOMAXPROCS=1 ./main


experiment:
	$(MAKE) comp
	$(MAKE) run

.PHONY: clean

clean:
	rm -f main enclavebin
