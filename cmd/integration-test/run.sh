#!/bin/bash

# reading os type from arguments
CURRENT_OS=$1

if [ "${CURRENT_OS}" == "windows-latest" ];then
    extension=.exe
fi

echo "::group::Building integration-test binary"
go build -o integration-test$extension
echo "::endgroup::"

echo "::group::Building cvemap binary from current branch"
go build -o cvemap$extension ../cvemap
echo "::endgroup::"


echo 'Starting cvemap integration test'
./integration-test$extension -current cvemap$extension
