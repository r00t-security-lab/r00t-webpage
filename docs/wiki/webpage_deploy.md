---
sidebar: auto
--- 

# www.r00team.cc 首页部署指南

## vuepress

关于**vuepress**的介绍请查看[Vuepress-快速上手](https://vuepress.vuejs.org/zh/guide/getting-started.html)

需要先安装nodejs、yarn

在本项目目录运行`yarn`拉取依赖

## 文档编写部署

1. clone项目

```sh
git clone git@github.com:r00t-security-lab/r00t-webpage.git
```

2. 编辑文档

在docs添加文档，各个目录的首页默认页面为`README.md`，记得添加链接索引

3. 预览文档效果

```sh
yarn docs:dev
```

4. 使用deploy.sh部署

```sh
deploy.sh "commit message"
```
