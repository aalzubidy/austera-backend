#!/bin/bash

set -e
echo "---> BEGIN: Pre-commit hook <---"

# Lint and test
npm run lint
npm run test

# NPM run version
BRANCH=`git branch | grep \* | cut -d ' ' -f2`
IFS="/"
TYPE=($BRANCH)
if [ "${TYPE[0]}" = "patch" ]; then
	npm --no-git-tag-version version patch
elif [ "${TYPE[0]}" = "minor" ]; then
	npm --no-git-tag-version version minor
elif [ "${TYPE[0]}" = "major" ]; then
	npm --no-git-tag-version version major
else
	npm --no-git-tag-version version patch
fi

# Attach updated files
rm -rf package-lock.json
npm install
git add package.json package-lock.json

echo "---> END: Pre-commit hook <---"
