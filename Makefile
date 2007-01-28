
all: 
	@(cd src; make all)

test: all
	(cd tests; make all)

clean:
	@echo "Cleaning..."
	@(cd src; make clean)
	@(cd tests; make clean)
	@rm -rf bin

