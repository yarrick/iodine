
all: 
	(cd src; make all)

stateos:
	@echo OS is $(OS)

clean:
	@echo "Cleaning..."
	(cd src; make clean)
	@rm -rf bin

