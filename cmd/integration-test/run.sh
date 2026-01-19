#!/bin/bash

# reading os type from arguments
CURRENT_OS=$1

if [ "${CURRENT_OS}" == "windows-latest" ];then
    extension=.exe
fi

echo "::group::Building integration-test binary"
go build -o integration-test$extension
echo "::endgroup::"

echo "::group::Building vulnx binary from current branch"
go build -o vulnx$extension ../vulnx
echo "::endgroup::"


echo 'Starting integration tests'
./integration-test$extension -vulnx vulnx$extension
