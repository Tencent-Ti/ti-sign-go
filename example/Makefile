
TARGET_OS=linux
TARGET_ARCH=amd64
TARGET_PREFIX=TI
BINARY=ti-sign-example

.PHONY: default
default: clean build


.PHONY: build
build:
		 GO111MODULE=on GOOS=${TARGET_OS} GOARCH=${TARGET_ARCH} go build -o ${BINARY}

.PHONY: clean
clean:
		if [ -d $(BINARY) ]; then rm $(BINARY) ; fi