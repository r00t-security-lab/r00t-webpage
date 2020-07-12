#!/usr/bin/env sh

if [ $# != 1 ];then
echo "$0 \"commit message\""
exit
fi

# 确保脚本抛出遇到的错误
set -e

# 生成静态文件
npm run docs:build

git add .
git commit -m "$1"
git push

cd web

echo 'www.r00team.cc' > CNAME

git init
git add -A
git commit -m 'upload'

git push -f git@github.com:dhu-r00t/dhu-r00t.github.io.git master

cd -
